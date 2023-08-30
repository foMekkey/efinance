<?php
require 'Initiation.php';
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
header("Response_Code: 000");
$req = file_get_contents('php://input');
file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/pgw/response.txt", serialize($req));
header("Response_Code: 000");
$initiator = new Initiation();
$senderId = $_REQUEST['SenderID'];
$senderRequestNumber = $_REQUEST['SenderRequestNumber'];
$requestObject = $_REQUEST['RequestObject'];
$signature = $_REQUEST['Signature'];
$fileOpened = $_SERVER['DOCUMENT_ROOT'] . '/pgw/orders/' . $senderRequestNumber . '.log';
$orderNo = file_get_contents($fileOpened);
file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/pgw/order.txt", "Order No is: ----  " . $orderNo);
$silentCall = $initiator->silentCall($requestObject, $senderRequestNumber);
file_put_contents("decrypted.txt", serialize($test));
file_put_contents($_SERVER['DOCUMENT_ROOT'] . "/pgw/decrypted.txt", serialize($silentCall));
?>
