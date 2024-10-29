=== Plugin Name ===
Contributors: acsteam
Tags: authentication, login, Windows Azure, Access Control Service, ACS
Requires at least: 3.0
Tested up to: 3.1.1
Stable tag: trunk

The plugin allows WordPress hosts to enable federated login for their WordPress site using Windows Azure AppFabric Access Control Service (ACS) 2.0.

== Description ==

The ACS WordPress Plugin allows WordPress hosts to enable federated login for their WordPress site using Windows Azure AppFabric Access Control Service (ACS) 2.0. 

WordPress administrators can use ACS to create trust relationships between their site and identity providers such as Windows Live ID, Facebook, Google, Yahoo!, and custom identity providers such as Microsoft Active Directory Federation Services 2.0. The ACS WordPress Plugin then renders a custom login page based on the ACS configuration, and enables end users to log in to the WordPress site using an identity provider of their choice.

= Features = 

* Authenticate to WordPress using Windows Live ID, Facebook, Google, Yahoo!, and custom web-based identity providers configured in ACS

* Easy registration for WordPress site subscribers

* Manage the WordPress site using a federated account

* Federated accounts are identical to normal user accounts and support fallback to local password-based authentication

* Integrates with ACS using the WS-Federation protocol and Simple Web Tokens

= Requirements =

* A Windows Azure account at http://windows.azure.com 

* A registered ACS 2.0 namespace (for details on how to create a namespace, see http://msdn.microsoft.com/en-us/library/ee725233.aspx )
  
* Web host running PHP 5.0 or greater

* Web host running WordPress 3.0 or greater

For more information about Windows Azure AppFabric Access Control Service (ACS) 2.0, see the following page:

http://acs.codeplex.com

== Installation ==

See the following page for installation instructions:

http://acs.codeplex.com/wikipage?title=WordPress%20Plugin

== Other Notes ==

= License =
This code released under the terms of the New BSD License (BSD).

== Changelog ==

= 1.0 =
* Initial release of the ACS WordPress Plugin. 

= 1.0.1 =
* Resolved issue with empty unique IDs for custom WS-Federation identity providers 
