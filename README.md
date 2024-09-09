# SDN Network Routing

##### A project created by Stefan Gore and Francesco Pietri for the Softwarize course

## Documentation

- The documentation about the controller can be found in this file: [![View PDF](https://img.shields.io/badge/View-PDF-red)](Softwarized_Network.pdf)
- The documentation about the topologies can be found in this file: [![Documentation_Topologies](https://img.shields.io/badge/README-Book-orange?logo=readthedocs)](topologies/README.md)

## How to Demo

1. **Install the Comnetsemu environment:** Follow the instructions in this guide: [Comnetsemu Labs Guide](https://www.granelli-lab.org/researches/relevant-projects/comnetsemu-labs)
   
2. **Clone this repository:**
   - Enter the Comnetsemu environment, navigate to a folder of your choice, and clone this repository:
     ```bash
     git clone https://github.com/GoreStefan/sdn_network_routing
     ```

3. **Run the controller and topology:**
   - Open two terminal tabs:
     - In the first tab, execute:
       ```bash
       ryu-manager Controller.py
       ```
       This initializes the controller.
     - In the second tab, navigate to the `topologies` folder and run the topology of your choice, for example:
       ```bash
       cd topologies
       sudo python3 PreTopology.py
       ```

4. **Test real-time features:**
   - Wait for the controller to install the forwarding table inside the switches, then you can test the following features:
     - **Link Failure:** Bring down a link (e.g., `link s1 s2 down`)
     - **Switch Failure:** Simulate a switch failure (e.g., `switch s1 down`)
     - **Host Migration:** Migrate a host (e.g., `migrate h1 s1 s2`)

## Demo Video
[![Watch the video](https://img.youtube.com/vi/zhclnHBGCf0/maxresdefault.jpg)](https://youtu.be/zhclnHBGCf0)


## Troubleshooting

- If Mininet does not close properly, run the following command before starting the controller again:
  ```bash
  sudo mn -c
