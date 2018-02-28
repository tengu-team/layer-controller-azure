# !/usr/bin/env python3
# Copyright (C) 2017 Qrama
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
# pylint: disable=c0111,c0301,c0325,r0903,w0406,c0103

from os import remove
from shutil import copyfile

from charms.reactive import when, when_not, set_flag, clear_flag
from charmhelpers.core.hookenv import status_set, charm_dir
from charmhelpers.core.host import service_restart, chownr


@when('sojobo.available')
@when_not('controller-azure.installed')
def install(sojobo):
    api_dir = list(sojobo.connection())[0]['api-dir']
    copyfile('{}/files/controller_azure.py'.format(charm_dir()), '{}/controllers/controller_azure.py'.format(api_dir))
    copyfile('{}/files/bootstrap_azure_controller.py'.format(charm_dir()), '{}/scripts/bootstrap_azure_controller.py'.format(api_dir))
    copyfile('{}/files/add_azure_credential.py'.format(charm_dir()), '{}/scripts/add_azure_credential.py'.format(api_dir))
    chownr(api_dir, 'sojobo', 'www-data', chowntopdir=True)
    service_restart('nginx')
    status_set('active', 'data copied')
    set_flag('controller-azure.installed')


@when('sojobo.removed', 'controller-azure.installed')
def remove_controller(sojobo):
    api_dir = list(sojobo.connection())[0]['api-dir']
    remove('{}/controllers/controller_azure.py'.format(api_dir))
    remove('{}/scripts/bootstrap_azure_controller.py'.format(api_dir))
    remove('{}/scripts/add_azure_credential.py'.format(api_dir))
    service_restart('nginx')
    clear_flag('controller-azure.installed')
