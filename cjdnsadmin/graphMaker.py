# You may redistribute this program and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

def makeGraph():
    import cjdnsadmin.adminTools as admin
    import networkx as nx
    from cjdnsadmin.publicToIp6 import PublicToIp6_convert
    from collections import deque

    cjdns=admin.connect()
    root=admin.whoami(cjdns)
    rootIP=root['IP']

    G=nx.Graph()
    G.add_node(rootIP[-4:],ip=rootIP)

    nodes=deque()
    nodes.append(rootIP)
    while len(nodes) != 0:
        parentIP=nodes.popleft()
        resp=cjdns.NodeStore_nodeForAddr(parentIP)
        numLinks=0
        if b'result' in resp:
            link=resp[b'result']
            if b'linkCount' in link:
                numLinks=int(resp[b'result'][b'linkCount'])
                G.nodes[parentIP[-4:]]['version']=resp[b'result'][b'protocolVersion']

        for i in range(0,numLinks):
            resp = cjdns.NodeStore_getLink(i, parent=parentIP)
            childLink=resp[b'result']
            if not childLink: continue
            childAddr=admin.parseAddr(childLink[b'child'])
            childIP=PublicToIp6_convert(childAddr[b'publicKey'])
            # Check to see if its one hop away from parent node
            if childLink[b'isOneHop'] != 1:
                continue
            # If its a new node then we want to follow it
            if not childIP[-4:] in G.nodes():
                G.add_node(childIP[-4:],ip=childIP)
                G.nodes[childIP[-4:]]['version']=0
                nodes.append(childIP)
            # If there is not a link between the nodes we should put one there
            if (not childIP[-4:] in G[parentIP[-4:]]):
                G.add_edge(parentIP[-4:],childIP[-4:])

    return G
