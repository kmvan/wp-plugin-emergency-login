<?php

// Plugin Name: INN Emergency Login | INN 紧急登录
// Plugin URI: https://inn-studio.com/emergency-login
// Description: See plugin official website. | 具体使用说明请参阅插件官网。
// Author: Km.Van
// Version: 1.0.0
// Author URI: https://inn-studio.com
// PHP Required: 7.2

namespace InnStudio\Plugins\InnEmergencyLogin;

\defined('AUTH_KEY') || \http_response_code(500) && die;

class InnEmergencyLogin
{
    public function __construct(string $removePageUrl = '')
    {
        \add_action('plugins_loaded', [$this, 'filterPluginsLoaded']);
    }

    public function filterPluginsLoaded(): void
    {
        if (\defined('DOING_AJAX') && \DOING_AJAX) {
            return;
        }

        if (\current_user_can('manage_options')) {
            return;
        }

        $this->loginWithAdmin();
    }

    private function genToken(): string
    {
        return \hash('sha512', \AUTH_KEY);
    }

    private function loginWithAdmin(): void
    {
        $token = (string) \filter_input(\INPUT_GET, 'token', \FILTER_SANITIZE_STRING);

        if ( ! $token || $token !== $this->genToken()) {
            return;
        }

        global $wpdb;

        $metaValue = 'a:1:{s:13:"administrator";b:1;}';
        $sql       = <<<SQL
SELECT `user_id` FROM `{$wpdb->prefix}usermeta`
WHERE `meta_key` = 'wp_capabilities'
AND `meta_value` = %s
SQL;
        $meta = $wpdb->get_row($wpdb->prepare(
            $sql,
            $metaValue
        ));

        if ( ! $meta) {
            return;
        }

        \wp_set_current_user($meta->user_id);
        \wp_set_auth_cookie($meta->user_id, true);

        $url = \get_admin_url();
        echo <<<HTML
<a href="{$url}">OK</a>
HTML;

        die;
    }
}

new InnEmergencyLogin();
