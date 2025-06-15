<?php
/**
 * Plugin Name: Lafapay Payment Gateway
 * Plugin URI: https://xixixipay.fun
 * Description: Accept cryptocurrency payments that utilize Li.Fi in your WooCommerce store.
 * Version: 1.0.1
 * Author: Fahmi Lukistriya
 * Author URI: https://fahmilukis.space
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: lafapay-payment-gateway
 * Domain Path: /languages
 */

defined("ABSPATH") or exit();

// Add Blocks support
add_action("woocommerce_blocks_loaded", "lafapay_register_block_support");
function lafapay_register_block_support()
{
    if (
        class_exists(
            "Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType"
        )
    ) {
        require_once plugin_dir_path(__FILE__) .
            "includes/class-lafapay-blocks-support.php";
        add_action(
            "woocommerce_blocks_payment_method_type_registration",
            function (
                Automattic\WooCommerce\Blocks\Payments\PaymentMethodRegistry $payment_method_registry
            ) {
                $payment_method_registry->register(
                    new WC_Lafapay_Blocks_Support()
                );
            }
        );
    }
}

add_filter("woocommerce_payment_gateways", "lafapay_add_gateway_class");
function lafapay_add_gateway_class($gateway)
{
    $gateway[] = "WC_Lafapay_Gateway";

    // Debug: Check if gateway is being added
    if (defined("WP_DEBUG") && WP_DEBUG) {
        error_log("Lafapay: Gateway class added to WooCommerce");
    }

    return $gateway;
}

add_action("plugins_loaded", "lafapay_init_gateway_class");
function lafapay_init_gateway_class()
{
    // Check if WooCommerce is active
    if (!class_exists("WC_Payment_Gateway")) {
        return;
    }

    class WC_Lafapay_Gateway extends WC_Payment_Gateway
    {
        public function __construct()
        {
            $this->id = "lafapay";
            $this->icon = "";
            $this->has_fields = true;
            $this->method_title = "Lafapay";
            $this->method_description =
                "Accept USDC from users on any blockchain including Ethereum L2s and Solana using Li.Fi's cross-chain payment infrastructure.";

            // Add support for subscriptions and other features
            $this->supports = ["products", "refunds"];

            // Initialize settings
            $this->init_form_fields();
            $this->init_settings();

            // Get settings values
            $this->title = $this->get_option("title", "Cryptocurrency Payment");
            $this->description = $this->get_option(
                "description",
                "Pay with USDC from any blockchain"
            );
            $this->enabled = $this->get_option("enabled", "yes");
            $this->evm_wallet = $this->get_option("evm_wallet");
            $this->svm_wallet = $this->get_option("svm_wallet");
            $this->lifi_sdk_key = $this->get_option("lifi_sdk_key");

            // Check if gateway is properly configured
            if (empty($this->evm_wallet) && empty($this->svm_wallet)) {
                $this->enabled = "no";
                add_action("admin_notices", [
                    $this,
                    "admin_notice_wallet_required",
                ]);
            }

            add_action(
                "woocommerce_update_options_payment_gateways_" . $this->id,
                [$this, "process_admin_options"]
            );

            add_action("wp_enqueue_scripts", [$this, "payment_scripts"]);
            add_action("woocommerce_api_lafapay_webhook", [$this, "webhook"]);
            add_action("woocommerce_receipt_" . $this->id, [
                $this,
                "receipt_page",
            ]);
        }

        public function init_form_fields()
        {
            $saved_evm_wallet = get_option("lafapay_evm_wallet_address", "");
            $saved_svm_wallet = get_option("lafapay_svm_wallet_address", "");
            $saved_sdk_key = get_option("lafapay_sdk_key", "");

            $this->form_fields = [
                "enabled" => [
                    "title" => "Enable/Disable",
                    "type" => "checkbox",
                    "label" => "Enable Lafapay Payment Gateway",
                    "default" => "yes",
                ],
                "title" => [
                    "title" => "Title",
                    "type" => "text",
                    "description" =>
                        "This controls the title which the user sees during checkout.",
                    "default" => "Cryptocurrency Payment",
                    "desc_tip" => true,
                ],
                "description" => [
                    "title" => "Description",
                    "type" => "textarea",
                    "description" =>
                        "This controls the description which the user sees during checkout.",
                    "default" =>
                        "Pay with USDC from any blockchain using our secure cross-chain payment system.",
                    "desc_tip" => true,
                ],
                "evm_wallet" => [
                    "title" => "EVM Wallet Address (0x...)",
                    "type" => "text",
                    "description" =>
                        "Enter your EVM-compatible wallet address where you want to receive payments.",
                    "default" => $saved_evm_wallet,
                    "placeholder" => "0x...",
                    "desc_tip" => true,
                ],
                "svm_wallet" => [
                    "title" => "SVM Wallet Address",
                    "type" => "text",
                    "description" =>
                        "Enter your SVM-compatible wallet address where you want to receive payments.",
                    "default" => $saved_svm_wallet,
                    "desc_tip" => true,
                ],
                "wallet_help" => [
                    "title" => "Wallet Setup",
                    "type" => "title",
                    "description" =>
                        'If you don\'t have a wallet yet, you can create one using MetaMask (for EVM) or a compatible SVM wallet. <a href="https://metamask.io/" target="_blank">Download MetaMask here</a>.',
                ],
                "lifi_sdk_key" => [
                    "title" => "LiFi SDK Key",
                    "type" => "password",
                    "description" =>
                        "Enter your LiFi SDK key for cross-chain functionality.",
                    "default" => $saved_sdk_key,
                    "desc_tip" => true,
                ],
            ];
        }

        public function is_available()
        {
            // Check if enabled
            if ("yes" !== $this->enabled) {
                return false;
            }

            // Check if at least one wallet is configured
            if (empty($this->evm_wallet) && empty($this->svm_wallet)) {
                return false;
            }

            // Check if WooCommerce is properly configured
            if (!$this->get_option("title")) {
                return false;
            }

            return parent::is_available();
        }

        public function admin_notice_wallet_required()
        {
            ?>
            <div class="notice notice-error">
                <p><?php _e(
                    "Lafapay Payment Gateway: Please configure at least one wallet address (EVM or SVM) in the payment settings.",
                    "lafapay-payment-gateway"
                ); ?></p>
            </div>
            <?php
        }

        public function payment_fields()
        {
            if ($this->description) {
                echo wpautop(wp_kses_post($this->description));
            } ?>
            <div id="lafapay-payment-form">
                <p>
                    <label for="lafapay-network">Select Network:</label>
                    <select id="lafapay-network" name="lafapay_network" required>
                        <option value="">Choose a network...</option>
                        <option value="ethereum">Ethereum</option>
                        <option value="polygon">Polygon</option>
                        <option value="arbitrum">Arbitrum</option>
                        <option value="optimism">Optimism</option>
                        <option value="solana">Solana</option>
                        <option value="bsc">Binance Smart Chain</option>
                    </select>
                </p>

                <div id="lafapay-payment-info" style="display: none;">
                    <p><strong>Payment Details:</strong></p>
                    <div id="lafapay-amount"></div>
                    <div id="lafapay-recipient"></div>
                </div>
            </div>
            <?php
        }

        public function payment_scripts()
        {
            if (
                !is_cart() &&
                !is_checkout() &&
                !isset($_GET["pay_for_order"]) &&
                !has_block("woocommerce/checkout")
            ) {
                return;
            }

            // if our payment gateway is disabled, we do not have to enqueue JS too
            if ("no" === $this->enabled) {
                return;
            }

            // Check if files exist before enqueuing
            $js_file =
                plugin_dir_path(__FILE__) . "assets/js/lafapay-payment.js";
            $css_file =
                plugin_dir_path(__FILE__) . "assets/css/lafapay-payment.css";

            if (file_exists($js_file)) {
                wp_enqueue_script(
                    "lafapay-payment-js",
                    plugin_dir_url(__FILE__) . "assets/js/lafapay-payment.js",
                    ["jquery"],
                    "1.0.1",
                    true
                );

                wp_localize_script("lafapay-payment-js", "lafapay_params", [
                    "ajax_url" => admin_url("admin-ajax.php"),
                    "nonce" => wp_create_nonce("lafapay_nonce"),
                    "lifi_sdk_key" => $this->lifi_sdk_key,
                ]);
            }

            if (file_exists($css_file)) {
                wp_enqueue_style(
                    "lafapay-payment-css",
                    plugin_dir_url(__FILE__) . "assets/css/lafapay-payment.css",
                    [],
                    "1.0.1"
                );
            }
        }

        public function validate_fields()
        {
            // Skip validation if no fields are submitted (for other payment methods)
            if (
                !isset($_POST["payment_method"]) ||
                $_POST["payment_method"] !== $this->id
            ) {
                return true;
            }

            if (empty($_POST["lafapay_network"])) {
                wc_add_notice("Please select a payment network.", "error");
                return false;
            }

            if (empty($_POST["lafapay_wallet_address"])) {
                wc_add_notice("Please enter your wallet address.", "error");
                return false;
            }

            $wallet_address = sanitize_text_field(
                $_POST["lafapay_wallet_address"]
            );
            $network = sanitize_text_field($_POST["lafapay_network"]);

            // Validate wallet address format based on network
            if (
                in_array($network, [
                    "ethereum",
                    "polygon",
                    "arbitrum",
                    "optimism",
                    "bsc",
                ])
            ) {
                if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $wallet_address)) {
                    wc_add_notice(
                        "Invalid EVM wallet address format.",
                        "error"
                    );
                    return false;
                }
            } elseif ($network === "solana") {
                if (
                    strlen($wallet_address) < 32 ||
                    strlen($wallet_address) > 44
                ) {
                    wc_add_notice(
                        "Invalid Solana wallet address format.",
                        "error"
                    );
                    return false;
                }
            }

            return true;
        }

        public function process_payment($order_id)
        {
            $order = wc_get_order($order_id);

            if (!$order) {
                return ["result" => "fail", "message" => "Order not found"];
            }

            // Check if this is our payment method
            if (
                isset($_POST["payment_method"]) &&
                $_POST["payment_method"] === $this->id
            ) {
                $network = sanitize_text_field($_POST["lafapay_network"]);
                $wallet_address = sanitize_text_field(
                    $_POST["lafapay_wallet_address"]
                );

                // Store payment details in order meta
                $order->update_meta_data("_lafapay_network", $network);
                $order->update_meta_data(
                    "_lafapay_customer_wallet",
                    $wallet_address
                );
                $order->update_meta_data(
                    "_lafapay_payment_id",
                    uniqid("lafapay_" . $order_id . "_")
                );

                // Determine recipient wallet based on network
                $recipient_wallet = "";
                if (
                    in_array($network, [
                        "ethereum",
                        "polygon",
                        "arbitrum",
                        "optimism",
                        "bsc",
                    ])
                ) {
                    $recipient_wallet = $this->evm_wallet;
                } elseif ($network === "solana") {
                    $recipient_wallet = $this->svm_wallet;
                }

                $order->update_meta_data(
                    "_lafapay_recipient_wallet",
                    $recipient_wallet
                );
                $order->save();
            }

            $order->update_status(
                "pending",
                __(
                    "Awaiting cryptocurrency payment confirmation",
                    "lafapay-payment-gateway"
                )
            );

            wc_reduce_stock_levels($order_id);
            WC()->cart->empty_cart();

            return [
                "result" => "success",
                "redirect" => $this->get_return_url($order),
            ];
        }

        public function receipt_page($order_id)
        {
            $order = wc_get_order($order_id);
            $network = $order->get_meta("_lafapay_network");
            $recipient_wallet = $order->get_meta("_lafapay_recipient_wallet");
            $payment_id = $order->get_meta("_lafapay_payment_id");

            echo '<div id="lafapay-payment-receipt">';
            echo "<h3>Complete Your Cryptocurrency Payment</h3>";
            echo "<p><strong>Order ID:</strong> " .
                esc_html($order_id) .
                "</p>";
            echo '<p><strong>Amount:</strong> $' .
                esc_html($order->get_total()) .
                " USDC</p>";
            echo "<p><strong>Network:</strong> " .
                esc_html(ucfirst($network)) .
                "</p>";
            echo "<p><strong>Recipient Address:</strong> <code>" .
                esc_html($recipient_wallet) .
                "</code></p>";
            echo '<div id="lafapay-lifi-widget" data-order-id="' .
                esc_attr($order_id) .
                '" data-payment-id="' .
                esc_attr($payment_id) .
                '"></div>';
            echo "</div>";
        }

        public function webhook()
        {
            $raw_body = file_get_contents("php://input");
            $decoded_body = json_decode($raw_body, true);

            // Verify webhook signature if needed
            $headers = getallheaders();

            if (!$this->verify_webhook_signature($raw_body, $headers)) {
                status_header(401);
                exit("Unauthorized");
            }

            if (
                !isset($decoded_body["payment_id"]) ||
                !isset($decoded_body["status"])
            ) {
                status_header(400);
                exit("Bad Request");
            }

            $payment_id = sanitize_text_field($decoded_body["payment_id"]);
            $status = sanitize_text_field($decoded_body["status"]);
            $tx_hash = isset($decoded_body["transaction_hash"])
                ? sanitize_text_field($decoded_body["transaction_hash"])
                : "";

            // Find order by payment ID
            $orders = wc_get_orders([
                "meta_key" => "_lafapay_payment_id",
                "meta_value" => $payment_id,
                "limit" => 1,
            ]);

            if (empty($orders)) {
                status_header(404);
                exit("Order not found");
            }

            $order = $orders[0];

            switch ($status) {
                case "completed":
                    $order->payment_complete($tx_hash);
                    $order->add_order_note(
                        sprintf(
                            __(
                                "Lafapay payment completed. Transaction hash: %s",
                                "lafapay-payment-gateway"
                            ),
                            $tx_hash
                        )
                    );
                    break;

                case "failed":
                    $order->update_status(
                        "failed",
                        __("Lafapay payment failed.", "lafapay-payment-gateway")
                    );
                    break;

                case "pending":
                    $order->update_status(
                        "on-hold",
                        __(
                            "Lafapay payment is being processed.",
                            "lafapay-payment-gateway"
                        )
                    );
                    break;
            }

            if ($tx_hash) {
                $order->update_meta_data("_lafapay_transaction_hash", $tx_hash);
                $order->save();
            }

            status_header(200);
            exit("OK");
        }

        private function verify_webhook_signature($payload, $headers)
        {
            // Implement webhook signature verification
            // This is a placeholder - implement according to LiFi's webhook security
            $signature = isset($headers["X-LiFi-Signature"])
                ? $headers["X-LiFi-Signature"]
                : "";

            if (empty($signature)) {
                return false;
            }

            // Example verification (adjust according to LiFi's actual implementation)
            $expected_signature = hash_hmac(
                "sha256",
                $payload,
                $this->lifi_sdk_key
            );

            return hash_equals($expected_signature, $signature);
        }

        public function process_admin_options()
        {
            $saved = parent::process_admin_options();

            // Save wallet addresses to separate options for easy access
            update_option(
                "lafapay_evm_wallet_address",
                $this->get_option("evm_wallet")
            );
            update_option(
                "lafapay_svm_wallet_address",
                $this->get_option("svm_wallet")
            );
            update_option("lafapay_sdk_key", $this->get_option("lifi_sdk_key"));

            return $saved;
        }
    }
}

// Add custom order status for crypto payments
add_action("init", "lafapay_register_order_status");
function lafapay_register_order_status()
{
    register_post_status("wc-crypto-pending", [
        "label" => "Crypto Payment Pending",
        "public" => true,
        "exclude_from_search" => false,
        "show_in_admin_all_list" => true,
        "show_in_admin_status_list" => true,
        "label_count" => _n_noop(
            'Crypto Payment Pending <span class="count">(%s)</span>',
            'Crypto Payment Pending <span class="count">(%s)</span>'
        ),
    ]);
}

// Add custom order status to WooCommerce
add_filter("wc_order_statuses", "lafapay_add_order_status");
function lafapay_add_order_status($order_statuses)
{
    $new_order_statuses = [];

    foreach ($order_statuses as $key => $status) {
        $new_order_statuses[$key] = $status;
        if ("wc-pending" === $key) {
            $new_order_statuses["wc-crypto-pending"] = "Crypto Payment Pending";
        }
    }

    return $new_order_statuses;
}

// AJAX handler for payment status check
add_action("wp_ajax_lafapay_check_payment", "lafapay_check_payment_status");
add_action(
    "wp_ajax_nopriv_lafapay_check_payment",
    "lafapay_check_payment_status"
);

function lafapay_check_payment_status()
{
    check_ajax_referer("lafapay_nonce", "nonce");

    $order_id = intval($_POST["order_id"]);
    $order = wc_get_order($order_id);

    if (!$order) {
        wp_die("Order not found", 404);
    }

    wp_send_json([
        "status" => $order->get_status(),
        "payment_complete" => $order->is_paid(),
    ]);
}
