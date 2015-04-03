# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This driver api is adopted from a blueprint implementation what was
# started by Gary Duan, vArmour. That implementation was eventually abandoned.

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class L3RouterBaseDriver(object):

    @abc.abstractmethod
    def create_router_precommit(self, context, router_context):
        """Perform operations specific to the router type in preparation for
        the creation of a new router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the new
        router.

        Create a new router, allocating resources as necessary in the
        database. Called inside transaction context on session. Call cannot
        block. Raising an exception will result in a rollback of the current
        transaction.
        """
        pass

    @abc.abstractmethod
    def create_router_postcommit(self, context, router_context):
        """Create a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the new
        router.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Raising an exception will cause the deletion of
        the resource.
        """
        pass

    @abc.abstractmethod
    def update_router_precommit(self, context, router_context):
        """Perform operations specific to the router type in preparation for
        the update of a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the new
        state of the router, as well as the original state prior to the
        update_router call.

        Update values of a router, updating the associated resources in the
        database. Called inside transaction context on session. Raising an
        exception will result in rollback of the transaction.

        update_router_precommit is called for all changes to the router
        state. It is up to the router type driver to ignore state or state
        changes that it does not know or care about.
        """
        pass

    @abc.abstractmethod
    def update_router_postcommit(self, context, router_context):
        """Update a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the new
        state of the router, as well as the original state prior to the
        update_router call.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Raising an exception will cause the deletion of
        the resource.

        update_router_postcommit is called for all changes to the router
        state.  It is up to the routertype driver to ignore state or state
        changes that it does not know or care about.
        """
        pass

    @abc.abstractmethod
    def delete_router_precommit(self, context, router_context):
        """Perform operations specific to the routertype in
        preparation for the deletion of a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the current
        state of the router, prior to the call to delete it.

        Delete router resources previously allocated by this routertype
        driver for a router. Called inside transaction context on session.
        Runtime errors are not expected, but raising an exception will
        result in rollback of the transaction.
        """
        pass

    @abc.abstractmethod
    def delete_router_postcommit(self, context, router_context):
        """Delete a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the current
        state of the router, prior to the call to delete it.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Runtime errors are not expected, and will not
        prevent the resource from being deleted.
        """
        pass

    @abc.abstractmethod
    def schedule_router_precommit(self, context, router_context):
        """Perform operations specific to the routertype in preparation for
        scheduling of a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the current
        state of the router, prior to the call to schedule it.

        Perform operations that need to happen before scheduling of routers
        of this routertype. Called inside transaction context on session.
        Raising an exception will result in rollback of the transaction.
        """
        pass

    @abc.abstractmethod
    def schedule_router_postcommit(self, context, router_context):
        """Schedule the router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the current
        state of the router, prior to the call to schedule it.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Raising an exception will cause un-scheduling of
        the router.
        """
        pass

    @abc.abstractmethod
    def unschedule_router_precommit(self, context, router_context):
        """Perform operations specific to the routertype in preparation for
        un-scheduling of a router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the current
        state of the router, prior to the call to schedule it.

        Perform operations that need to happen before un-scheduling of routers
        of this routertype. Called inside transaction context on session.
        Raising an exception will result in rollback of the transaction.
        """
        pass

    @abc.abstractmethod
    def unschedule_router_postcommit(self, context, router_context):
        """Un-schedule the router.

        :param context: the neutron context of the request
        :param router_context: RouterContext instance describing the current
        state of the router, prior to the call to schedule it.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Raising an exception will cause re-scheduling of
        the router.
        """
        pass

    @abc.abstractmethod
    def add_router_interface_precommit(self, context, r_port_context):
        pass

    @abc.abstractmethod
    def add_router_interface_postcommit(self, context, r_port_context):
        pass

    @abc.abstractmethod
    def remove_router_interface_precommit(self, context, r_port_context):
        pass

    @abc.abstractmethod
    def remove_router_interface_postcommit(self, context, r_port_context):
        pass


    @abc.abstractmethod
    def update_floatingip_precommit(self, context, fip_context):
        """Perform operations specific to the routertype in preparation for
        the update of a floatingip.

        :param context: the neutron context of the request
        :param fip_context: FloatingipContext instance describing the new
        state of the floatingip, as well as the original state prior
        to the update_floatingip call.

        Update values of a floatingip, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_floatingip_precommit is called for all changes to the
        floatingip state. It is up to the routertype driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    @abc.abstractmethod
    def update_floatingip_postcommit(self, context, fip_context):
        """Update a floatingip.

        :param context: the neutron context of the request
        :param fip_context: FloatingipContext instance describing the new
        state of the floatingip, as well as the original state prior
        to the update_floatingip call.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Raising an exception will cause the deletion of
        the resource.

        update_flotingip_postcommit is called for all changes to the router
        state.  It is up to the routertype driver to ignore state or state
        changes that it does not know or care about.
        """
        pass

    @abc.abstractmethod
    def delete_floatingip_precommit(self, context, fip_context):
        """Perform operations specific to the routertype in preparation for
        the deletion of a floatingip.

        :param context: the neutron context of the request
        :param fip_context: FloatingipContext instance describing the current
        state of the floatingip, prior to the call to delete it.

        Delete floatingip resources previously allocated by this routertype
        driver for a floatingip. Called inside transaction context on session.
        Runtime errors are not expected, but raising an exception will result
        in rollback of the transaction.
        """
        pass

    @abc.abstractmethod
    def delete_floatingip_postcommit(self, context, fip_context):
        """Delete a floatingip.

        :param context: the neutron context of the request
        :param fip_context: FloatingipContext instance describing the current
        state of the floatingip, prior to the call to delete it.

        Called after the transaction commits. Call can block, though will
        block the entire process so care should be taken to not drastically
        affect performance. Runtime errors are not expected, and will not
        prevent the resource from being deleted.
        """
        pass