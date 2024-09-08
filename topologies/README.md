# Topology Folder Explanation

## Introduction

Inside this folder, we have four different files: two for utility purposes and two for describing the actual topologies.

### Utility Files

- **CustomCLI**: A library providing a class that extends the default Mininet CLI, allowing us to execute custom commands.
- **TopologyTools**: A library of general-purpose functions and classes used by the topologies.

### Topology Files

- **PreTopology**: A simple network topology, described as follows:
    ![PreTopology](topologies/PreTopologyScheme.jpeg)

- **RedundantNetwork**: A more complex and redundant network topology, described as follows:
    ![RedundantNetwork](topologies/RedundantNetworkScheme.jpeg)

## Description of Main Components in TopologyTools

### Functions

- **`startIperf(host1, host2, bw, port, timeTotal)`**: Starts an Iperf traffic flow between two hosts with a fixed bandwidth (`bw`), port, and duration (`timeTotal`). This traffic generates ARP requests that are redirected to the controller, which computes the optimal path between the two hosts.
  
- **`pause_iperf(host)`**: Pauses the Iperf traffic on a specified host.

- **`resume_iperf(host)`**: Resumes the Iperf traffic on a specified host.

- **`terminate_iperf_on_host(host)`**: Terminates the Iperf server running on the specified host.

### Class: `MobilitySwitch`

This class extends the `OVSSwitch` and adds methods for reattaching and renaming interfaces. This functionality is required to implement live migration of a host from one switch to another while the Mininet network is running.

## Description of CustomCLI

The `CustomCLI` defines a new class `MyCLI`, which extends the default Mininet `CLI` and implements a new command called `migrate`. 

### Command: `migrate`

```python
def do_migrate(self, line):
    "Execute host migration"
    args = line.split()
    if len(args) != 3:
        print("Usage: migrate <host> <oldSwitch> <newSwitch>")      
        return

    host_name, old_switch_name, new_switch_name = args

    # Retrieve host and switches from the Mininet object
    h, old = self.mn.get(host_name, old_switch_name)
    new = self.mn[new_switch_name]

    # Terminate all Iperf servers to avoid issues due to pending ARP requests
    for ho in self.mn.hosts:
        terminate_iperf_on_host(ho)

    time.sleep(2)  # Allow some time for Iperf to fully terminate

    print(f"**** MIGRATION PROCESS START for {host_name} ****")
    # Move host to the new switch
    hintf, sintf = moveHost(h, old, new)
    print(f"**** MIGRATION PROCESS END for {host_name} ****")

    # Restart the Iperf traffic between hosts
    h0 = self.mn.hosts[0]
    for ho in self.mn.hosts:
        start_new_thread(startIperf, (ho, h0, 2.75, 5001, 20))

    print_topology(self.mn)
```

### Function: `moveHost`

```python
def moveHost(host, oldSwitch, newSwitch, newPort=None):
    "Move a host from the old switch to the new switch"
    hintf, sintf = host.connectionsTo(oldSwitch)[0]
    oldSwitch.moveIntf(sintf, newSwitch, port=newPort)
    return hintf, sintf
```

This function performs the migration of the host from the old switch to the new switch. It utilizes methods from the `MobilitySwitch` class to reattach the interface.

## General Description of a Suitable Topology for Our Controller

```python
def four_switches_network():
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8', 
                  link=TCLink, 
                  switch=MobilitySwitch)  # Ensure switches are of type MobilitySwitch!
```

This defines a Mininet topology where switches are specified as `MobilitySwitch` to allow host migrations.

### Setting Up the Controller

```python
controllerIP = '127.0.0.1'
info('*** Adding controller\n')
c0 = net.addController(name='c0',
                       controller=RemoteController,
                       ip=controllerIP,
                       protocol='tcp',
                       port=6633)
```

### Adding Switches, Hosts, and Links

```python
info('*** Add switches\n')
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
s4 = net.addSwitch('s4')

info('*** Add hosts\n')
h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')
h4 = net.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:04')
h5 = net.addHost('h5', ip='10.0.0.5', mac='00:00:00:00:00:05')
h6 = net.addHost('h6', ip='10.0.0.6', mac='00:00:00:00:00:06')

info('*** Add links between switches\n')
net.addLink(s1, s2, delay='10ms', bw=3)
net.addLink(s2, s3, delay='10ms', bw=3)
net.addLink(s1, s4, delay='14ms', bw=4)
net.addLink(s4, s3, delay='14ms', bw=4)

info('*** Add links between hosts and switches\n')
net.addLink(h1, s1)
net.addLink(h2, s1)
net.addLink(h3, s1)
net.addLink(h4, s3)
net.addLink(h5, s3)
net.addLink(h6, s3)
```

### Starting the Network

```python
info('*** Starting network\n')
net.build()

info('*** Starting controllers\n')
for controller in net.controllers:
    controller.start()

info('*** Starting switches\n')
start_switches(net, ['s1', 's2', 's3', 's4'], c0)

time.sleep(5)  # Do not remove this! Synchronization errors may occur if traffic starts too early.
```

### Starting Iperf Traffic

```python
print("Starting iperf")
start_new_thread(startIperf, (h1, h4, 2.75, 5001, timeTotal))
start_new_thread(startIperf, (h2, h5, 1.75, 5001, timeTotal))
start_new_thread(startIperf, (h3, h6, 1.75, 5001, timeTotal))
```

### Running the Custom CLI

```python
print_topology(net)
MyCLI(net)
net.stop()
```
