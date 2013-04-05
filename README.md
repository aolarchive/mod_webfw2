Mod_webfw2 is an Apache 2.x module that facilitates the blocking of malicious HTTP traffic. This module was consciously designed for performance, stability and reliability.

Fundamentally the module works just like a firewall. You define a filter and assign one or more rules within. An incoming set of data will continually traverse the rules until a match has been found. If no matches are found a default action will be taken.

Rules consist of a flow operation, matchers, and modifiers. Matchers are simply data to compare against a set of inputs, while a modifier is an action to be taken if a match is found.

Mod_webfw2 determines whether a configuration file has been modified and read in the changes. This means that the server does not require a restart in order to load new rule-sets.

It is released under the BSD license.
