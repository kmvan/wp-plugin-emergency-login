<?php

// Plugin Name: INN Emergency Login | INN 紧急登录
// Plugin URI: https://inn-studio.com/emergency-login
// Description: See plugin official website. | 具体使用说明请参阅插件官网。
// Author: INN STUDIO
// Version: 2.0.1
// Author URI: https://inn-studio.com
// PHP Required: 7.3

declare(strict_types=1);

namespace InnStudio\Plugin\InnEmergencyLogin;

\defined('AUTH_KEY') || http_response_code(500) && exit;

final class InnEmergencyLogin
{
    private const TOKEN_KEY = 'innEmergencyLoginToken';

    public function __construct()
    {
        add_action('plugins_loaded', function (): void {
            if (\defined('DOING_AJAX') && DOING_AJAX) {
                return;
            }

            if (current_user_can('manage_options')) {
                return;
            }

            $this->loginWithAdmin();
        });
    }

    private function genToken(): string
    {
        return hash('sha512', AUTH_KEY);
    }

    private function getAdminRoleId(): string
    {
        global $wpdb;

        $roles = get_option("{$wpdb->prefix}user_roles") ?: get_option('wp_user_roles') ?: [];

        if ( ! $roles) {
            return '';
        }

        foreach ($roles as $roleId => $role) {
            $caps = $role['capabilities'] ?? [];

            if ( ! $caps) {
                continue;
            }

            if ((bool) ($caps['manage_options'] ?? false)) {
                return $roleId;
            }
        }

        return '';
    }

    private function loginWithAdmin(): void
    {
        $token = (string) filter_input(\INPUT_GET, self::TOKEN_KEY, \FILTER_DEFAULT);

        if ( ! $token || $token !== $this->genToken()) {
            return;
        }

        global $wpdb;

        $sql = <<<SQL
SELECT `user_id` FROM `{$wpdb->prefix}usermeta`
WHERE (
    `meta_key` = '{$wpdb->prefix}capabilities'
    OR
    `meta_key` = 'wp_capabilities'
)
AND `meta_value` LIKE %s
LIMIT 0, 1
SQL;
        $meta = $wpdb->get_row($wpdb->prepare(
            $sql,
            "%{$this->getAdminRoleId()}%"
        ));

        if ( ! $meta) {
            exit('Unable to locate admin user.');
        }

        wp_set_current_user((int) $meta->user_id);
        wp_set_auth_cookie((int) $meta->user_id, true);

        $adminUrl = get_admin_url();

        echo <<<HTML
<a href="{$adminUrl}">✔️ Logged as administrator.</a>
HTML;

        exit;
    }
}

new InnEmergencyLogin();
