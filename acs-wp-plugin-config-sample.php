<?php
/*
ACS Plugin for Wordpress
Copyright (c) 2011, Microsoft Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL MICROSOFT BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/*******  REQUIRED SETTINGS  *******/

//Update the values below with information about your ACS configuration
define('ACS_NAMESPACE', 		'-------------INSERT ACS NAMESPACE FQDN-------------');
define('ACS_APPLICATION_REALM', '-------------INSERT REALM FOR RELYING PARTY APPLICATION-------------'); 
define('ACS_TOKEN_SIGNING_KEY', '-------------INSERT SIGNING KEY FOR RELYING PARTY APPLICATION-------------');
define('ACS_TOKEN_SIGNING_KEY_OLD', ''); //use only during key updates
//note: For testing locally, use a realm with 127.0.0.1 instead of localhost


/*******  ADVANCED SETTINGS  *******/

//Claim type mappings for WP user data
define('USER_UUID', 	'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'); //required
define('USER_IDP', 		'http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider'); //required
define('USER_EMAIL', 	'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
define('USER_NICKNAME', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name');

//token type (currently only SWT 1.0 tokens are supported)
define('ACS_TOKEN_TYPE', 	'http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0');

?>