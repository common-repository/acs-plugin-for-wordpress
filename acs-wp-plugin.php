<?php
/**
 * @package acs-wp-plugin
 * @version 1.0.1
 */
/*
Plugin Name: ACS Plugin for WordPress
Plugin URI: http://acs.codeplex.com
Description: Enables federated login for the WordPress site using Windows Azure AppFabric Access Control Service (ACS) 2.0
Author: Microsoft
Author URI: http://www.microsoft.com/
Version: 1.0.1
License: New BSD License (3-clause)

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

require_once('acs-wp-plugin-config.php');
require_once('lib/swt.php');
require_once('lib/wsfederation.php');
require_once( ABSPATH . WPINC . '/registration.php' );

DEFINE('acs_user_uuid', 'acs_user_uuid');
DEFINE('acs_identity_provider', 'acs_identity_provider');

//This plugin overrides the wp_authenticate function, which handles user login
if ( !function_exists('wp_authenticate') ) :
	function wp_authenticate($username = "", $password = "") 
	{
		//Check to see if a token is being posted from ACS (using the WS-Federation protocol)
		if ( @$_POST['wresult'] ) 
		{	
			//Decode the response if it was reposted as part of the account creation form (see below)
			$wresult = (array_key_exists('user_login', $_POST)) ? urldecode($_POST['wresult']) : $_POST['wresult'];
			
			//Parse token and extract information (i.e. claims) about the user
			try
			{
				$handler = new TokenReponseHandler();
				$token = $handler->HandleResponse($wresult, ACS_APPLICATION_REALM, ACS_TOKEN_TYPE);
				$validator = new TokenValidator();
				$validator->Validate($token, ACS_APPLICATION_REALM, ACS_NAMESPACE, ACS_TOKEN_SIGNING_KEY, ACS_TOKEN_SIGNING_KEY_OLD);
				$claims = $validator->GetClaims($token);
			} 
			catch (Exception $e) 
			{
				$user = new WP_Error('login_error', $e->getMessage());
				return $user;
			}
			
			//check for required UUID and IDP claims
			if ( empty($claims[USER_UUID]) )
			{
				$user = new WP_Error('login_error', 'No user ID was returned from the selected identity provider');
				return $user;
				
			}
			elseif ( empty($claims[USER_IDP]) )
			{
				$user = new WP_Error('login_error', 'No identity provider claim was returned');
				return $user;
				
			}
			
			//look up the user profile based on the unique ID and identity provider claims received
			$user = acs_get_user($claims[USER_IDP], $claims[USER_UUID]);
			
			//create user account if one doesn't exist
			if (!$user)
			{	
				//show the account creation form
				if (!array_key_exists('user_login', $_POST))
				{
					acs_create_user_form($wresult, $claims);
					exit;
				}
				//handle the response from the account creation form
				else
				{
					$user_login = sanitize_user( $_POST['user_login'] );
					$user_email = empty($claims[USER_EMAIL]) ? apply_filters('user_registration_email', $_POST['user_email']) : $claims[USER_EMAIL];
					$errors = new WP_Error();
					
					//check username
					if (username_exists($user_login)) 
					{
						$errors->add( 'username_exists', __( '<b>ERROR</b>: This username is already registered, please choose another one.' ) );
					} 
					elseif (!validate_username($user_login)) 
					{
						$errors->add( 'invalid_username', __( '<b>ERROR</b>: This username is invalid because it uses illegal characters. Please enter a valid username.' ) );	
					}
					elseif (empty($user_login)) 
					{
						$errors->add( 'empty_username', __( '<b>ERROR</b>: Please enter a valid username.' ) );	
					}
					
					//check email
					if ( $user_email == '' || !is_email($user_email)) 
					{
						$errors->add( 'invalid_email', __( '<b>ERROR</b>: Please enter a valid e-mail address.' ) );
					} 
					elseif (email_exists($user_email)) 
					{
						$errors->add( 'email_exists', __( '<b>ERROR</b>: This email is already registered. Please log in using a different account.' ) );
					}
					
					//display form if errors occurred
					if ( $errors->get_error_code() )
					{
						acs_create_user_form($wresult, $claims, $errors, $user_login, $user_email);
						exit;
					}				
				}
					
				//map user identity claims received to WordPress user attributes
				$userData['user_login'] = acs_escape_string($user_login);
				$userData['user_pass'] = sha1(strval(rand()).$claims[USER_UUID]); //creates a random password so the local account is protected
				$userData['display_name'] = acs_escape_string($user_login);
				$userData['nickname'] = acs_escape_string($user_login);
				$userData['user_email'] = acs_escape_string($user_email);
				$userData['wp_capabilities'] = "subscriber";
				$userData['user_registered'] = date('Y-m-d H:i:s');	
			    
				//write new WordPress user account to database
				$user_id = wp_insert_user($userData);
				if (is_numeric($user_id))
				{
					$user = new WP_user($user_id);
					//store metadata for the identity provider used, and the unique ID. 
					add_user_meta( $user_id, acs_user_uuid, acs_escape_string($claims[USER_UUID]) );
					add_user_meta( $user_id, acs_identity_provider, acs_escape_string($claims[USER_IDP]) );
				}	
				elseif ($user_id instanceof WP_Error)
				{
					$user = $user_id;
				}
				else
				{
					$user = new WP_Error('login_error', 'Problem creating an acccount (non-numeric ID returned)');
				}
				
				//debug
				//foreach ($userData as $key => $value)
				//{
				//	print "<script type='text/javascript'>alert(\"".$key." => ".$value."\")</script>";
				//}
				//print "<script type='text/javascript'>alert(\"UUID => ".acs_escape_string($claims[USER_UUID])."\")</script>";
				//print "<script type='text/javascript'>alert(\"IDP => ".acs_escape_string($claims[USER_IDP])."\")</script>";
			}
		}
		//handle WordPress login normally if not receving a token from ACS
		else
		{
			$username = sanitize_user($username);
			$password = trim($password);
		
			$user = apply_filters('authenticate', null, $username, $password);
		
			if ( $user == null ) {
				$user = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username or incorrect password.'));
			}
		
			$ignore_codes = array('empty_username', 'empty_password');
		
			if (is_wp_error($user) && !in_array($user->get_error_code(), $ignore_codes) ) {
				do_action('wp_login_failed', $username);
			}	
		}
	
		return $user;
	}
endif;

//This function looks up a user account based on the unique ID and identity provider claims received from ACS
function acs_get_user($idp, $uuid) 
{	
	//return false if arguments are empty
	if ( empty($idp) || empty($uuid) ) return false;
	
	global $wpdb;
	$sql = $wpdb->prepare("SELECT a.* FROM $wpdb->usermeta as a LEFT JOIN $wpdb->usermeta as b ON a.user_id = b.user_id WHERE (a.meta_key = %s AND a.meta_value = %s) AND (b.meta_key = %s AND b.meta_value = %s)", acs_user_uuid, $uuid, acs_identity_provider, $idp);
	$lookup = $wpdb->get_results( $sql );
	
	//return false if no data found
	if ( is_null($lookup) || !count($lookup) ) return false;
	
	//if multiple accounts were found for a user, return an error
	if (count($lookup) != 1)
	{
		$user = new WP_Error('login_error', 'More than one WordPress user ID was returned. This is an error. Please contact the WordPress administrator. '.$sql);
		return $user;
	}
	
	$row_id = @$lookup[0]->user_id;
	
	//ensure the user ID is valid
	if (intval($row_id) == 0)
	{
		$user = new WP_Error('login_error', 'An invalid WordPress user ID was returned. Please contact the WordPress administrator.');
		return $user;
	}

	$user = new WP_User($row_id);

	return $user;
}

//This function displays an account creation form so users can enter a username, plus an email address if we didn't get that information from the identity provider
function acs_create_user_form($wresult, $claims, $errors = null, $user_login = null, $user_email = null)
{
	login_header(__('Registration Form'), '<p class="message register">' . __('Create a username for this site') . '</p>', $errors);
?>

	<form name="create_user_form" action="<?php echo site_url('wp-login.php', 'login_post') ?>" method="post">
		<p>
			<label><?php _e('Username') ?><br />
			<input type="text" name="user_login" id="user_login" class="input" value="<?php echo esc_attr(stripslashes($user_login)); ?>" size="20" tabindex="10" /></label><br/>
			<!--<?php _e('This username will be used as a display name for your account.') ?>-->
		</p>
		<br class="clear" />
		<p>
			<label><?php _e('E-mail') ?><br />
			<input type="text" name="user_email" id="user_email" class="input" value="<?php echo esc_attr( stripslashes( empty($claims[USER_EMAIL]) ? $user_email : $claims[USER_EMAIL] ) ); ?>" size="20" tabindex="10" <?php echo empty($claims[USER_EMAIL]) ? '' : 'DISABLED'; ?> /></label><br/>
		</p>
		<br class="clear" />
		<input type="hidden" name="wresult" value="<?php echo urlencode( $wresult ); ?>" />
		<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Register'); ?>" tabindex="100" /></p>
	</form>
	
	<p id="nav">
	<a href="<?php echo site_url('wp-login.php', 'login') ?>"><?php _e('Log in') ?></a> 
	</p>
	
	<?php
	
}

//This function is for escaping string values
function acs_escape_string($string)
{
	return addslashes($string);	
}

//This function generates the URL for the ACS home realm discovery JSON feed, which is what tells the plugin what identity providers (and their login URLs) to display based on the ACS service configuration
function acs_login_page_feed_url()
{
	return "https://".ACS_NAMESPACE."/v2/metadata/IdentityProviders.js?protocol=wsfederation&realm=".ACS_APPLICATION_REALM."&version=1.0&callback=ShowSigninPage";	
}

//This function generates CSS for the login page
function acs_css() {
	print '
	<style type="text/css"> 		 
		div.SignInContent
		{
			text-align: center;
			margin-left: auto;
			margin-right: auto;
			position: relative;
			width: 100%;
			height: 100%;
		}
		 
		div.Header
		{
			padding:10px 10px;
			text-align: left;
			margin-left: auto;
			margin-right: auto;
			margin-bottom: 10px;
		}
		 
		div.LeftArea
		{
			width: 100%; 
			height: 100%;
		}
		 
		button.IdentityProvider
		{
			width: 250px;
			height: 30px;
			text-align: center;
			border: solid 1px #BBBBBB;
			margin-left: auto;
			margin-right: auto;
			margin-bottom: 5px;
			position: relative;
			cursor: pointer;
			font-size: 15px;
			color: blue;
			background: #F7F7F7;
			background: -webkit-gradient(linear, left top, left bottom, from(#FFFFFF), to(#EEEEEE));
			background: -moz-linear-gradient(bottom, #EEEEEE, #FFFFFF);
			filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0, StartColorStr=#FFFFFF, EndColorStr=#EEEEEE);
		}
		 
		img.IdentityProviderImage 
		{ 
			vertical-align: middle;
			postion: relative;
		}
		 
		button.IdentityProvider:hover 
		{ 
			background: #EEEEEE;
			background: -moz-linear-gradient(bottom, #DDDDDD, #FFFFFF);
			background: -webkit-gradient(linear, left top, left bottom, from(#FFFFFF), to(#DDDDDD));
			filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0, StartColorStr=#FFFFFF, EndColorStr=#DDDDDD);
		}
		 
		label
		{
			color: red;
		}
		</style>
	';
}

//This function generates the login page
function acs_login_form() {
	print '
	<div id="Main" style="display:none">
	    <div id="SignInContent" class="SignInContent">
		    <div id="LeftArea" class="LeftArea" style="display:none;">
		    	<hr id="HeaderLine" style="height: 1px;" />
			    <div id="Header" class="Header">Or, sign in using your account on:</div>  
			    <div id="HeaderAlt" class="Header" style="display:none">Sign in using your account on:</div> 
			    <div id="IdentityProvidersList"></div><br />
			    <div id="MoreOptions" style="display:none;"><a href="" onclick="ShowDefaultSigninPage(); return false;">Show more options</a></div>
		    </div> 
	    </div>
	</div><br />
	
	<script language="javascript" type="text/javascript">
        var identityProviders = [];
        var cookieName = "ACSChosenIdentityProvider";
        var cookieExpiration = 30; // days
        var maxImageWidth = 240;
        var maxImageHeight = 40;
 
        // This function will be called back by the HRD metadata, and is responsible for displaying the sign-in page.
        function ShowSigninPage(json) {
            var cookieName = GetHRDCookieName();
            var numIdentityProviderButtons = 0;
            var showMoreOptionsLink = false;
            identityProviders = json;

            // Loop through the identity providers
            for (var i in identityProviders) {
                // Show all sign-in options if no cookie is set
                if (cookieName === null) {
                    CreateIdentityProviderButton(identityProviders[i]);
                    numIdentityProviderButtons++;
                }
                // Show only the last selected identity provider if a cookie is set
                else {
                    if (cookieName == identityProviders[i].Name) {
                        CreateIdentityProviderButton(identityProviders[i]);
                        numIdentityProviderButtons++;
                    }
                    else {
                        showMoreOptionsLink = true;
                    }
                }
            }
            //If the user had a cookie but it didn\'t match any current identity providers, show all sign-in options 
            if (cookieName !== null && numIdentityProviderButtons === 0) {
                ShowDefaultSigninPage();
            }
            //Othewise, render the sign-in page normally
            else {
                ShowSigninControls(numIdentityProviderButtons, showMoreOptionsLink);
            }
            document.getElementById("Main").style.display = "";
        }
 
        // Resets the sign-in page to its original state before the user logged in and received a cookie.
        function ShowDefaultSigninPage() {
            var numIdentityProviderButtons = 0;
            document.getElementById("IdentityProvidersList").innerHTML = "";
            for (var i in identityProviders) {
                CreateIdentityProviderButton(identityProviders[i]);
                numIdentityProviderButtons++;
            }
            ShowSigninControls(numIdentityProviderButtons, false);
        }
 
        //Reveals the sign-in controls on the sign-in page, and ensures they are sized correctly
        function ShowSigninControls(numIdentityProviderButtons, showMoreOptionsLink) {
 
            //Display the identity provider links, and size the page accordingly
            if (numIdentityProviderButtons > 0) {
                document.getElementById("LeftArea").style.display = "";
            }
            //Show a link to redisplay all sign-in options
            if (showMoreOptionsLink) {
                document.getElementById("MoreOptions").style.display = "";
            }
            else {
                document.getElementById("MoreOptions").style.display = "none";
            }
        }
 
		//Creates a stylized link to an identity provider\'s login page
		function CreateIdentityProviderButton(identityProvider) {	
			var idpList = document.getElementById("IdentityProvidersList");
			var button = document.createElement("button");
			button.setAttribute("name", identityProvider.Name);
			button.setAttribute("id", identityProvider.LoginUrl );
			button.className = "IdentityProvider";
			button.onclick = IdentityProviderButtonClicked;
				
			// Display an image if an image URL is present
			if (identityProvider.ImageUrl.length > 0) {
				
				var img = document.createElement("img");
				img.className = "IdentityProviderImage";
				img.setAttribute("src", identityProvider.ImageUrl);
				img.setAttribute("alt", identityProvider.Name);
				img.setAttribute("border", "0");
				
				// If the image is larger than the button, scale maintaining aspect ratio.
		        if (img.height > maxImageHeight || img.width > maxImageWidth) {
		            var resizeRatio = 1;
		            if( img.width/img.height > maxImageWidth/maxImageHeight )
		            {
		                // Aspect ratio wider than the button
		                resizeRatio = maxImageWidth / img.width;
			        }
			        else
			        {
			            // Aspect ratio taller than or equal to the button
			            resizeRatio = maxImageHeight / img.height;
			        }
			        
                    img.setAttribute("height", img.height * resizeRatio);
			        img.setAttribute("width", img.width * resizeRatio);
		        }
				button.appendChild(img);
			}
			// Otherwise, display a text link if no image URL is present
			else if (identityProvider.ImageUrl.length === 0) {
				
				button.appendChild(document.createTextNode(identityProvider.Name));
			}
			idpList.appendChild(button);	
		}
 
        // Gets the name of the remembered identity provider in the cookie, or null if there isn\'t one.
        function GetHRDCookieName() {
            var cookie = document.cookie;
            if (cookie.length > 0) {
                var cookieStart = cookie.indexOf(cookieName + "=");
                if (cookieStart >= 0) {
                    cookieStart += cookieName.length + 1;
                    var cookieEnd = cookie.indexOf(";", cookieStart);
                    if (cookieEnd == -1) {
                        cookieEnd = cookie.length;
                    }
                    return unescape(cookie.substring(cookieStart, cookieEnd));
                }
            }
            return null;
        }
 
        // Sets a cookie with a given name
        function SetCookie(name) {
            var expiration = new Date();
            expiration.setDate(expiration.getDate() + cookieExpiration);
            document.cookie = cookieName + "=" + escape(name) + ";expires=" + expiration.toUTCString();
        }
 
        // Sets a cookie to remember the chosen identity provider and navigates to it.
        function IdentityProviderButtonClicked() {
	        if (window.event && window.event.keyCode == 13) return false;
            SetCookie(this.getAttribute("name"));
            window.location = this.getAttribute("id");
            return false;
        }

    </script>
	
	<script src="'.acs_login_page_feed_url().'" type="text/javascript"></script>
	';
}

add_action( 'login_head', 'acs_css' );
add_action( 'login_form', 'acs_login_form' );
add_action( 'register_form', 'acs_login_form' );

?>
