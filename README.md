goose-IEC61850-scapy
====================
The Generic Object Oriented Substation Events (GOOSE) protocol is defined in 
IEC 61850 for the purpose of distributing event data across entire 
substation networks.  The code in this project can be used to provide
assistance in decoding / encoding GOOSE packets in a programmatic way.

Most of the code was thrown together quickly and built so that we could use
it to specifically demonstrate an attack against GOOSE in our paper, 
published in the [IEEE Workshop on Smart Grid Communications](http://ieeexplore.ieee.org/xpl/login.jsp?tp=&arnumber=6477809&url=http%3A%2F%2Fieeexplore.ieee.org%2Fxpls%2Fabs_all.jsp%3Farnumber%3D6477809).
[[full text]](http://markdehus.com/SGCOMM.pdf).

The code comes with absolutely no warranty, and we are not liable if
it does something completely unexpected.  If you use this code in an
academic work, please cite our paper.

Please note that this code depends on the [scapy library](http://www.secdev.org/projects/scapy/).
