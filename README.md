# Shortest path and ecmp protocols implementation to ryu

In order to test the ryu's implementation of shortest path protocol and ecmp protocol it's necessary to run the mininet topology script and then eun the scrip for ryu.

## Mininet script
The mininet topology can be run whit the following command

´´´
sudo mn --custom fattree.py --topo fattree,4 --mac --switch ovsk --controller=remote,ip=IP_CONTROLLER,port=6633 
--link tc,bw=100,delay=5ms
´´´

## Ryu script
The ryu script can be run with the following command

´´´
ryu-manager --observe-links script.py
´´´

### Mac Learnig
After runned the mininet topology and the ryu script, the controller need to learn the mac address of the hosts into the network, for this reason it's necessary to exe a pingall command into the mininet CLI.

´´´
pingall
´´´

## Built With

* [Mininet](http://mininet.org) - The Network Emulator
* [Ryu](https://github.com/osrg/ryu) - The SDN Controller

## Authors

* **Alessio Carmenini** - *Initial work* - [Ryu](https://github.com/xf1rex/ryu)
