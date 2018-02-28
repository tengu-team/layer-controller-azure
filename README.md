# Info
This is a subordinate charm for the Sojobo-api which enables the use of Microsoft Azure.

# Installation
Clone this repository and build the charm, then deploy it.
```
juju deploy ./controller-google
juju add-relation sojobo-api controller-google
```
To disable Microsoft Azure, just remove the application.
**Warning: Removing this will prevent the use of existing Microsoft Azure clouds!**

# Bugs
Report bugs on <a href="https://github.com/tengu-team/layer-controller-azure/issues">Github</a>

# Authors
- Michiel Ghyselinck <michiel.ghyselinck@tengu.io>
