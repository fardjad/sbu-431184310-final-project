# SBU-431184310 (Spring 2017) Final Project

We had to implement [this](https://web.archive.org/web/20170803183108/https://www.ijircce.com/upload/2016/february/53_7_A%20Framework.pdf) paper for the final project. 
The algorithm described in the paper only takes into account the most 
recently installed temp flow packet count (even worse, it requests stats 
from the switch shortly after the flow is installed.) This will cause **ALL** 
source IP addresses to be blocked eventually.

After doing some research I realized that the publisher is identified as 
predatory by several sources and the aforementioned paper might not have gone 
through the standard assessment process of other respected publishers. 
Having this said, I had to do some modifications to the algorithm to make it 
work as expected. The whole method IMO is still very naive and fragile but 
this implementation can - at least - mitigate the attack scenarios described 
in the paper.

## Quick Start

1. Setup a Mininet VM
2. Copy **synfloodblocker.py** to `$HOME/pox/pox/misc`
3. Run `python $HOME/pox.py py --completion log.level --DEBUG misc.synfloodblocker`
4. Create a directory and copy all other python scripts to that directory.
5. cd to that directory and run `python topo.py`

## License
Except where otherwise noted, content on this repository is licensed under a 
[Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/).

