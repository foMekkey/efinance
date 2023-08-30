<?php

require 'Initiation.php';

$address = new Initiation();

$params = array(
    'senderId' => $_POST['sender_id'],
    'senderName' => $_POST['sender_name'],
    'password' => $_POST['efinance_password'],
    'serviceCode' => $_POST['service_code'],
    'accountCode' => $_POST['account_code'],
    'accountAmount' => $_POST['account_amount'],
    'paymentGatewayURL' => $_POST['payment_gateway_url'],
    'confirmationURL' => $_POST['confirmation_url'],
    'confirmationRedirectURL' => $_POST['confirmation_redirect_url'],
    'certificatePath' => 'certificates/InternetPaymentCrt.cer',
    'serverIp' => '::1',
	"client_order_id" => $address->GenerateRandomValue8(),
);

// Payment Mechanism
$data['paymentType'] = "Channel";
$data['paymentMechanism'] = "NotSet";
$data['mobileNo'] = "";
$data['email'] = "";

$mechanism = array(
    "type" => $data['paymentType'],
    "mechanismType" => $data['paymentMechanism'],
    "channelMobileNo" => $data['mobileNo'],
    "channelEmail" => $data['email'],
);

$url = $address->initiatePaymentRequest($params, $mechanism);

?>

<form method="post" id="initiationChannelForm"
action="<?php echo $_POST['payment_gateway_url'];?>" >
    <input type="hidden" name="SenderID" value="<?=$url['SenderID']?>">
    <input type="hidden" name="RandomSecret" value="<?=$url['RandomSecret']?>">
    <input type="hidden" name="RequestObject" value="<?=$url['RequestObject']?>">
    <input type="hidden" name="HasedRequestObject" value="<?=$url['HasedRequestObject']?>">
    <input type="submit" id="sendButton" value="send">
</form>
<script type="text/javascript">
document.getElementById("sendButton").style.display = "none";
document.getElementById("initiationForm").submit();
</script>