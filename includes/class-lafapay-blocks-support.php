<?php
/**
 * Lafapay WooCommerce Blocks support
 */

use Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType;

final class WC_Lafapay_Blocks_Support extends AbstractPaymentMethodType
{
    private $gateway;
    protected $name = "lafapay";

    public function initialize()
    {
        $this->settings = get_option("woocommerce_lafapay_settings", []);
        $gateways = WC()->payment_gateways->payment_gateways();
        $this->gateway = $gateways[$this->name];
    }

    public function is_active()
    {
        return $this->gateway->is_available();
    }

    public function get_payment_method_script_handles()
    {
        $script_path = "/assets/js/lafapay-blocks.js";
        $script_asset_path =
            plugin_dir_path(__FILE__) . "../assets/js/lafapay-blocks.asset.php";
        $script_asset = file_exists($script_asset_path)
            ? require $script_asset_path
            : [
                "dependencies" => [],
                "version" => "1.0.1",
            ];
        $script_url =
            plugin_dir_url(__FILE__) . "../assets/js/lafapay-blocks.js";

        wp_register_script(
            "wc-lafapay-payments-blocks",
            $script_url,
            $script_asset["dependencies"],
            $script_asset["version"],
            true
        );

        if (function_exists("wp_set_script_translations")) {
            wp_set_script_translations(
                "wc-lafapay-payments-blocks",
                "lafapay-payment-gateway"
            );
        }

        return ["wc-lafapay-payments-blocks"];
    }

    public function get_payment_method_data()
    {
        return [
            "title" => $this->get_setting("title"),
            "description" => $this->get_setting("description"),
            "enabled" => $this->get_setting("enabled") === "yes",
            "networks" => [
                "ethereum" => "Ethereum",
                "polygon" => "Polygon",
                "arbitrum" => "Arbitrum",
                "optimism" => "Optimism",
                "solana" => "Solana",
                "bsc" => "Binance Smart Chain",
            ],
        ];
    }
}
