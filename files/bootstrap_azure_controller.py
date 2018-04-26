# !/usr/bin/env python3
# Copyright (C) 2017  Qrama
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# pylint: disable=c0111,c0301,c0325,c0103,r0913,r0902,e0401,C0302, R0914
import asyncio
import logging
import os
import base64
import hashlib
from pathlib import Path
from subprocess import check_output, check_call
import traceback
import sys
import yaml
from juju import tag
from juju.controller import Controller
from juju.client import client
sys.path.append('/opt')
from sojobo_api import settings
from sojobo_api.api import w_datastore as datastore, w_juju as juju


async def bootstrap_azure_controller(c_name, region, cred_name, username, password):
    try:
        tengu_username = settings.JUJU_ADMIN_USER
        tengu_password = settings.JUJU_ADMIN_PASSWORD
        juju_cred_name = 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest())
        credential = juju.get_credential(username, cred_name)

        # Check if the credential is valid.
        juju.get_controller_types()['azure'].check_valid_credentials(credential)

        temp_cred = create_temporary_cred_file(juju_cred_name, credential)

        logger.info('Adding credential to JuJu...')
        check_call(['juju', 'add-credential', 'azure', '-f', temp_cred, '--replace'])

        logger.info('Bootstrapping controller in Azure cloud...')
        check_call(['juju', 'bootstrap', '--agent-version=2.3.0', 'azure',
                    c_name, '--credential', juju_cred_name])

        # Remove temporary credentials.
        os.remove(temp_cred)

        logger.info('Setting admin password...')
        check_output(['juju', 'change-user-password', 'admin', '-c', c_name],
                     input=bytes('{}\n{}\n'.format(tengu_password, tengu_password), 'utf-8'))

        logger.info('Updating controller in database...')
        con_data = update_controller_database(c_name)

        logger.info('Connecting to controller...')
        controller = Controller()
        await controller.connect(
            con_data['controllers'][c_name]['api-endpoints'][0],
            tengu_username, tengu_password, con_data['controllers'][c_name]['ca-cert'])

        user_info = datastore.get_user(username)
        juju_username = user_info["juju_username"]
        user = tag.user(juju_username)

        logger.info('Adding existing credentials to new controller...')
        await update_credentials_new_controller(controller, username, juju_username, cred_name)

        model_facade = client.ModelManagerFacade.from_connection(
                        controller.connection)
        controller_facade = client.ControllerFacade.from_connection(controller.connection)
        if username != tengu_username:
            user_facade = client.UserManagerFacade.from_connection(controller.connection)
            users = [client.AddUser(display_name=juju_username,
                                    username=juju_username,
                                    password=password)]
            await user_facade.AddUser(users)
            changes = client.ModifyControllerAccess('superuser', 'grant', user)
            await controller_facade.ModifyControllerAccess([changes])

        logger.info('Adding default models to database...')
        await add_default_models_to_database(c_name, cred_name, username, juju_username, controller, user_info)

        logger.info('Controller succesfully created!')
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        datastore.set_controller_state(c_name, 'error')
    finally:
        if 'controller' in locals():
            await juju.disconnect(controller)


def create_temporary_cred_file(juju_cred_name, credential):
    """Creates tempory credential file that can be used in the JuJu CLI."""
    path = '/tmp/credentials.yaml'
    data = {'credentials':
                {'azure':
                    {juju_cred_name:
                        {'auth-type': 'service-principal-secret',
                         'application-id': credential['credential']['application-id'],
                         'application-password': credential['credential']['application-password'],
                         'subscription-id': credential['credential']['subscription-id']
                        }
                    }
                }
            }
    with open(path, 'w') as dest:
        yaml.dump(data, dest, default_flow_style=False)
    return path


def update_controller_database(c_name):
    """Sets the controller to ready state. This function should be executed
    after the bootstrap of the controller."""
    controllers_yaml = os.path.join(str(Path.home()), '.local', 'share', 'juju',
                                    'controllers.yaml')
    with open(controllers_yaml, 'r') as data:
        con_data = yaml.load(data)
    datastore.set_controller_state(
        c_name,
        'ready',
        con_data['controllers'][c_name]['api-endpoints'],
        con_data['controllers'][c_name]['uuid'],
        con_data['controllers'][c_name]['ca-cert'])
    return con_data


async def add_default_models_to_database(c_name, cred_name, username, juju_username, controller, user_info):
    """Adds the default models, that have been created by new controller, to the
    database."""
    c_info = datastore.get_controller(c_name)
    model_facade = client.ModelManagerFacade.from_connection(
                    controller.connection)
    controller_facade = client.ControllerFacade.from_connection(controller.connection)
    user = tag.user(juju_username)
    models = await controller_facade.AllModels()
    for model in models.user_models:
        if model:
            m_key = juju.construct_model_key(c_info['name'], model.model.name)
            logger.info(model.model.name)
            if username != settings.JUJU_ADMIN_USER:
                model_tag = tag.model(model.model.uuid)
                changes = client.ModifyModelAccess('admin', 'grant', model_tag, user)
                await model_facade.ModifyModelAccess([changes])
            datastore.create_model(m_key, model.model.name, state='Model is being deployed', uuid='')
            datastore.add_model_to_controller(c_name, m_key)
            datastore.set_model_state(m_key, 'ready', credential=cred_name, uuid=model.model.uuid)
            datastore.set_model_access(m_key, username, 'admin')
            ssh_keys = user_info["ssh_keys"]
            if len(ssh_keys) > 0:
                juju.update_ssh_keys_model(username, ssh_keys, c_name, m_key)


async def update_credentials_new_controller(controller, username, juju_username, new_cred_name):
    """Adds the existing credentials (if any) to the new controller."""
    credentials = datastore.get_cloud_credentials('azure', username)
    for cred in credentials:
        if cred['type'] == 'azure':
            if username != settings.JUJU_ADMIN_USER:
                await juju.update_cloud(controller, 'azure', cred['name'], juju_username, username)
                logger.info('Added credential %s to controller ', cred['name'])
            elif cred['name'] != new_cred_name:
                await juju.update_cloud(controller, 'azure', cred['name'], juju_username, username)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('bootstrap_azure_controller')
    hdlr = logging.FileHandler('{}/log/bootstrap_azure_controller.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(bootstrap_azure_controller(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
    loop.close()
