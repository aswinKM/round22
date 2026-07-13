<?php

/**
 * Cloudstick Password Driver
 *
 * Updates mail user passwords stored in Dovecot passwd-files located at
 * /etc/exim4/domains/{domain}/passwd, one file per hosted domain.
 *
 * File format per line:
 *   username:{MD5}$1$salt$hash:uid:gid:gecos:home:shell:extra_fields
 *
 * Requirements:
 *   The PHP-FPM process user must have write access to the passwd files.
 *   Run as root: usermod -aG mail cloudhouse
 *   Run as root: find /etc/exim4/domains -name passwd -exec chmod 664 {} \;
 */
class rcube_cloudstick_password
{
    public function save($currpass, $newpass, $username)
    {
        $at = strrpos($username, '@');

        if ($at === false) {
            rcube::raise_error([
                'code'    => 600,
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Password plugin: Invalid username format (expected user@domain): $username",
            ], true, false);

            return PASSWORD_ERROR;
        }

        $local  = substr($username, 0, $at);
        $domain = substr($username, $at + 1);

        $passwdfile = "/etc/exim4/domains/{$domain}/passwd";

        if (!file_exists($passwdfile)) {
            rcube::raise_error([
                'code'    => 600,
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Password plugin: Passwd file not found: $passwdfile",
            ], true, false);

            return PASSWORD_CONNECT_ERROR;
        }

        $newpwhash = $this->hash_md5crypt($newpass);

        $fp = fopen($passwdfile, 'r+');

        if (!$fp) {
            rcube::raise_error([
                'code'    => 600,
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Password plugin: Cannot open passwd file for writing: $passwdfile",
            ], true, false);

            return PASSWORD_CONNECT_ERROR;
        }

        $content = '';
        $found   = false;
        $prefix  = $local . ':';

        if (flock($fp, LOCK_EX)) {
            while (($line = fgets($fp, 40960)) !== false) {
                $trimmed = rtrim($line, "\r\n");

                if ($trimmed !== '' && strncmp($trimmed, $prefix, strlen($prefix)) === 0) {
                    $fields    = explode(':', $trimmed);
                    $fields[1] = $newpwhash;
                    $line      = implode(':', $fields) . "\n";
                    $found     = true;
                }

                $content .= $line;
            }

            if (!$found) {
                flock($fp, LOCK_UN);
                fclose($fp);

                rcube::raise_error([
                    'code'    => 600,
                    'file'    => __FILE__,
                    'line'    => __LINE__,
                    'message' => "Password plugin: User '$local' not found in $passwdfile",
                ], true, false);

                return PASSWORD_ERROR;
            }

            rewind($fp);
            ftruncate($fp, 0);
            $written = fwrite($fp, $content);
            flock($fp, LOCK_UN);
            fclose($fp);

            if ($written === false) {
                rcube::raise_error([
                    'code'    => 600,
                    'file'    => __FILE__,
                    'line'    => __LINE__,
                    'message' => "Password plugin: Failed to write passwd file: $passwdfile",
                ], true, false);

                return PASSWORD_ERROR;
            }

            return PASSWORD_SUCCESS;
        }

        fclose($fp);

        rcube::raise_error([
            'code'    => 600,
            'file'    => __FILE__,
            'line'    => __LINE__,
            'message' => "Password plugin: Failed to lock passwd file: $passwdfile",
        ], true, false);

        return PASSWORD_ERROR;
    }

    /**
     * Generate an MD5-CRYPT hash with {MD5} prefix to match the existing passwd-file format.
     * Uses PHP crypt() with $1$ salt prefix.
     */
    private function hash_md5crypt($password)
    {
        $chars   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';
        $saltstr = '';

        for ($i = 0; $i < 8; $i++) {
            $saltstr .= $chars[random_int(0, 63)];
        }

        return '{MD5}' . crypt($password, '$1$' . $saltstr . '$');
    }
}
