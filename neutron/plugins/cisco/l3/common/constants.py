# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Bob Melander, Cisco Systems, Inc.
# @author: Hareesh Puthalath, Cisco Systems, Inc.

# Hosting device belong to one of the following categories:
VM_CATEGORY = 'VM'
HARDWARE_CATEGORY = 'Hardware'

# Default name of hosting device template for network nodes
# hosting Linux network namespace-based Neutron routers.
NETWORK_NODE_TEMPLATE = 'NetworkNode_template'

# Default name of router type for Neutron routers implemented
# as Linux network namespaces in network nodes.
NAMESPACE_ROUTER_TYPE = 'NetworkNamespace_router'

# Router status
# =============
# Created but not scheduled nor deployed
ROUTER_CREATED = 'Created'
#  Scheduling in progress
ROUTER_SCHEDULING = 'Scheduling'
# Backlogged due to unsuccessful scheduling attempt
ROUTER_BACKLOGGED = 'Backlogged'
# Backlogged due to non-ready hosting device (e.g., still booting)
ROUTER_WAITING_HOST = 'Awaiting host'
# Deployed and configured
ROUTER_ACTIVE = 'Active'
# Deletion in progress (by cfg agent)
ROUTER_DELETING = 'Deleting'

AGENT_TYPE_CFG = 'Cisco cfg agent'
CSR1kv_SSH_NETCONF_PORT = 22

# Topic for Cisco configuration agent
CFG_AGENT = 'cisco_cfg_agent'

# Service Types : Used for loading the Hosting device manager to load the right
# driver class for a particular service
SERVICE_ROUTING = "routing"

# Device Configuration Protocol
DEV_CFG_PROTO_NETCONF = "NETCONF"
DEV_CFG_PROTO_REST = "REST_API"

# Service VM status
SVM_OK = 'OK'
SVM_ERROR = 'ERROR'
SVM_NON_RESPONSIVE = 'NON_RESPONSIVE'
