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
import sys
import traceback
import logging
import ast
import hashlib
sys.path.append('/opt')
from juju import tag
from juju.client import client
from juju.controller import Controller
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as ds, w_juju as juju  #pylint: disable=C0413

class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD

async def add_credential(username, credentials):
    try:
        cred = ast.literal_eval(credentials)
        token = JuJu_Token()
        c_type = cred['type']
        credential_name = 't{}'.format(hashlib.md5(cred['name'].encode('utf')).hexdigest())
        controllers = ds.get_cloud_controllers(c_type)
        for con in controllers:
            controller = Controller()
            await controller.connect(con['api-endpoints'][0], token.username, token.password, con['ca-cert'])
            logger.info('%s -> Adding credentials', con['name'])
            await juju.update_cloud(controller, 'azure', cred['name'], username)
            logger.info('%s -> controller updated', con['name'])
            await controller.disconnect()
        ds.set_credential_ready(username, cred['name'])
        logger.info('Succesfully added credential')
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('add_azure_credential')
    hdlr = logging.FileHandler('{}/log/add_azure_credential.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(add_credential(sys.argv[1], sys.argv[2]))
loop.close()
