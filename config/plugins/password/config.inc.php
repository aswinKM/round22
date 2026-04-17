<?php

// Password Plugin options
// -----------------------

// Driver for password change: cloudstick handles /etc/exim4/domains/{domain}/passwd
$config['password_driver'] = 'cloudstick';

// Hashing algorithm — must match the {MD5}$1$... format in the passwd files
$config['password_algorithm'] = 'md5-crypt';

// Require the current (old) password to be entered before changing
$config['password_confirm_current'] = true;

// Minimum password length
$config['password_minimum_length'] = 8;

// Require at least one non-alpha character
$config['password_require_nonalpha'] = false;

// Log password changes to logs/password
$config['password_log'] = false;

// Logins exempt from password change (no Password tab shown)
$config['password_login_exceptions'] = null;

// Use unicode domain names (false = UTF-8, true = punycode)
$config['password_idn_ascii'] = false;
