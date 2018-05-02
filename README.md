# Info
This is a subordinate charm for the Sojobo-api which enables the use of Microsoft Azure.

# Installation

```
juju deploy cs:tengu-team/controller-azure
juju add-relation sojobo-api controller-azure
```
To disable Microsoft Azure, just remove the application.
**Warning: Removing this will prevent the use of existing Microsoft Azure clouds!**

# Bugs
Report bugs on <a href="https://github.com/tengu-team/layer-controller-azure/issues">Github</a>

# Authors
- Michiel Ghyselinck <michiel.ghyselinck@tengu.io>
