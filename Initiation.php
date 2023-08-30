<?php
//error_reporting(E_ALL);
//session_start();
//date_default_timezone_set("Africa/Cairo");
use SplFixedArray AS SplFixedArray;

class Initiation
{
    /**
     * @param array $params
     * * @param array $mechanism
     * @return array
     * @throws Exception
     */
    function initiatePaymentRequest(array $params, array $mechanism)
    {
        //print '<pre>'; print_r($params);exit;
        $path = $params['certificate_path'];//'certificates/InternetPaymentCrt.cer';
        $req = new PaymentRequestInitiationWebTransferReq();
        $orderInfo = $this->fillPaymentRequest($req, $params, $mechanism);
        $secret256 = null;
        $encryptedReq = $this->EncryptPaymentRequest($req, $path, $secret256);
        //print '<pre>'; print_r($encryptedReq);exit;
        $_SESSION['SN_Secret'] = $secret256;
        $senderID = $encryptedReq['SenderID'];
        $randomSecret = $encryptedReq['RandomSecret'];
        $requestObject = $encryptedReq['RequestObject'];
        $HasedRequestObject = $encryptedReq['HasedRequestObject'];
        $url = sprintf("%s?SenderID=%s&RandomSecret=%s&RequestObject=%s&HasedRequestObject=%s",
            $params['payment_gateway_url'],
            $senderID,
            $randomSecret,
            $requestObject,
            $HasedRequestObject);
        $arr = array('SenderID' => $senderID, 'RandomSecret' => $randomSecret,
            'RequestObject' => $requestObject, 'HasedRequestObject' => $HasedRequestObject);
        // print '<pre>'; print_r($arr); exit;
        return $arr;
    }

    /**
     * @param PaymentRequestInitiationWebTransferReq $req
     * @param $params
     * @param $mechanism
     * @return PaymentRequestInitiationReq
     */
    function fillPaymentRequest(PaymentRequestInitiationWebTransferReq $req, $params, $mechanism)
    {
        //print '<pre>'; print_r($params); exit;
        $path = $params['certificate_path'];//'certificates/InternetPaymentCrt.cer';
        //print '<pre>aaaaaaaaaa  '; print_r($path); exit;
        $sender = $this->CreateSenderObject(
            $params['sender_id'], $params['sender_name'],
            $params['efinance_password'], $path);
        $req->DecryptedRequestObject = new PaymentRequestInitiationReq();
        $req->DecryptedRequestObject->setSender($sender);
        $req->DecryptedRequestObject->SenderRequestNumber = $this->GenerateRandomValue16();// . '--' . $params['client_order_id'];
        $req->DecryptedRequestObject->SenderInvoiceNumber = $params['client_order_id'];
        $req->DecryptedRequestObject->RequestInitiationDescription = "Order Number: " . $params['client_order_id'];
        //$this->GenerateRandomValue16();
        $req->DecryptedRequestObject->ServiceCode = $params['service_code'];
        //$req->DecryptedRequestObject->RequestInitiationDescription = NULL;
        $req->DecryptedRequestObject->Currency = '818';
        $SettlementAmounts = new SettlementAmounts();
        $SettlementAmounts->SettlementAccountCode = $params['account_code'];
        $SettlementAmounts->SettlementAmountsDescription = '';
        $SettlementAmounts->Amount = $params['account_amount'];
        $req->DecryptedRequestObject->SettlementAmounts = array($SettlementAmounts);
        $req->DecryptedRequestObject->PaymentConfirmationUrl = $params['confirmation_url'];
        $req->DecryptedRequestObject->PaymentConfirmationRedirectUrl = $params['confirmation_redirect_url'];
        $req->DecryptedRequestObject->ExpiryDate = date("Y-m-d", strtotime('+6 hours'));
        $req->DecryptedRequestObject->IP = $params['server_ip'];
        $mechanism['mechanismType'] = "NotSet";
        $req->DecryptedRequestObject->setPaymentMechanism($this->CreateEmptyPaymentMechanismObject($mechanism));
        $req->DecryptedRequestObject->setUserUniqueIdentifier($this->GenerateRandomValue8());
        // print '<pre>'; print_r($req->DecryptedRequestObject);exit;
        return $req->DecryptedRequestObject;
    }

    /**
     * @param $senderId
     * @param $senderName
     * @param $password
     * @param $path
     * @return Sender
     */
    function CreateSenderObject($senderId, $senderName, $password, $path)
    {
        $sender = new Sender();
        $sender->Id = $senderId;
        $sender->Name = $senderName;
        $sender->RandomValue = $this->GenerateRandomValue32();
        $sender->Password = $this->EncryptByCertificate($password, $path);
        //print '<pre>rrrrrr '; print_r($sender); exit;
        return $sender;
    }

    /**
     * @return mixed
     */
    function GenerateRandomValue32()
    {
        $str = $this->gen_uuid();
        $newStr = str_replace("-", "", $str);
        return $newStr;
    }

    /**
     * @return string
     * The new function which is equivalent to Guid.NewGuid()
     * returnig uuidv4 UUIDV4 GUID sequence number
     */
    function gen_uuid()
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,
            // 48 bits for "node"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    /**
     * @param $secretClear16
     * @param $certificatePath
     * @return string
     */
    function EncryptByCertificate($secretClear16, $certificatePath)
    {
        //print '<pre>ffffff'; print $secretClear16 . "---------" . $certificatePath; exit;
        $pemFile = file_get_contents($certificatePath);
        //print '<pre>eeee'; print $pemFile; exit;
        $convertedFile = "-----BEGIN CERTIFICATE-----\n";
        $convertedFile .= chunk_split(base64_encode($pemFile), 64, "\n");
        $convertedFile .= "-----END CERTIFICATE-----";
        $key_resource = openssl_pkey_get_public($convertedFile);
        $encrypted = unpack('C*', '');
        openssl_public_encrypt(
            $secretClear16,
            $encrypted,
            $convertedFile);
        // while ($msg = openssl_error_string())
        //     echo $msg . "<br />\n";
        return base64_encode($encrypted);
    }

    /**
     * @return bool|string
     */
    function GenerateRandomValue16()
    {
        $r = $this->GenerateRandomValue32();
        return substr($r, 0, strlen($r) / 2);
    }

    /**
     * @param $mechanism
     * @return PaymentMechanism
     */
    function CreateEmptyPaymentMechanismObject($mechanism)
    {
        //print '<pre>'; print_r($mechanism); exit;
        $paymentMechanism = new PaymentMechanism();
        $paymentMechanism->setType($mechanism['type']);
        $paymentMechanism->setMechanismType($mechanism['mechanismType']);
        if ($mechanism['type'] == "Channel") {
            $channelPayment = new PaymentMechanismChannel();
            //print 'inside if';
            //$paymentMechanism->setMechanismType('Channel');
            $channelPayment->setMobileNumber('01148786727');
            $channelPayment->setEmail('test@gmail.com');
            $paymentMechanism->setChannel($channelPayment);
        } else if ($mechanism['type'] == "Card") {
            $paymentMechanism->setChannel($mechanism['channel']);
        }
        //print '<pre>'; print_r($paymentMechanism); exit;
        return $paymentMechanism;
    }

    /**
     * @return bool|string
     */
    function GenerateRandomValue8()
    {
        $r = $this->GenerateRandomValue32();
        return substr($r, 0, strlen($r) / 4);
    }

    /**
     * @param $req
     * @param $certificatePath
     * @param $secretClear16
     * @return array
     * @throws Exception
     */
    function EncryptPaymentRequest($req, $certificatePath, &$secretClear16)
    {
        $objSerialized = $this->SerializePaymentInitiationRequest($req);
        //print '<pre>'; print_r($req->DecryptedRequestObject); exit;
        //$this->returnOrderNo($req->DecryptedRequestObject->SenderRequestNumber);
        file_put_contents($_SERVER['DOCUMENT_ROOT'] . '/pgw/orders/' . $req->DecryptedRequestObject->SenderRequestNumber .
            '.log', $req->DecryptedRequestObject->SenderInvoiceNumber);
        $req->EncryptedRequestObject = $this->AESEncrypt($objSerialized, $req->DecryptedRequestObject->SenderRequestNumber);
        //print '<pre>'; print_r($req); exit;
        $req->setRandomSecret($this->EncryptByCertificate($req->EncryptedRequestObject['randomSecret'], $certificatePath));
        $req->HasedRequestObject = $this->HashSHA2($req->EncryptedRequestObject['encrypted']);
        //print '<pre>'; print_r($req); exit;
        $data = array();
        $data['SenderID'] = urlencode($req->DecryptedRequestObject->Sender->Id);
        $data['RandomSecret'] = urlencode($req->RandomSecret);
        $data['RequestObject'] = urlencode($req->EncryptedRequestObject['encrypted']);
        $data['HasedRequestObject'] = urlencode($req->HasedRequestObject);
        return $data;
    }

    /**
     * @param $obj
     * @param bool $isRoot
     * @return string
     */
    function SerializePaymentInitiationRequest($obj, $isRoot = True)
    {
        //print '<pre>'; print_r($obj->DecryptedRequestObject); exit;
        $id = $obj->DecryptedRequestObject->Sender->Id;
        $biller_name = $obj->DecryptedRequestObject->Sender->Name;
        $random = $obj->DecryptedRequestObject->Sender->RandomValue;
        $pass = $obj->DecryptedRequestObject->Sender->Password;
        $SettlementAccountCode = $obj->DecryptedRequestObject->SettlementAmounts[0]->SettlementAccountCode;
        $amount = $obj->DecryptedRequestObject->SettlementAmounts[0]->Amount;
        $SenderRequestNumber = $obj->DecryptedRequestObject->SenderRequestNumber;
        $SenderInvoiceNumber = $obj->DecryptedRequestObject->SenderInvoiceNumber;
        $ServiceCode = $obj->DecryptedRequestObject->ServiceCode;
        $Currency = $obj->DecryptedRequestObject->Currency;
        $ip = $obj->DecryptedRequestObject->IP;
        $PaymentMechanismType = $obj->DecryptedRequestObject->PaymentMechanism->Type;
        $MechanismType = $obj->DecryptedRequestObject->PaymentMechanism->MechanismType;
        $ChannelMobileNumber = $obj->DecryptedRequestObject->PaymentMechanism->Channel->MobileNumber;
        $ChannelEmail = $obj->DecryptedRequestObject->PaymentMechanism->Channel->Email;
        $ExpiryDate = $obj->DecryptedRequestObject->ExpiryDate;
        $PaymentConfirmationUrl = $obj->DecryptedRequestObject->PaymentConfirmationUrl;
        $PaymentConfirmationRedirectUrl = $obj->DecryptedRequestObject->PaymentConfirmationRedirectUrl;
        $UserUniqueIdentifier = $obj->DecryptedRequestObject->UserUniqueIdentifier;
        $string3 = '<?xml version="1.0" encoding="utf-16"?><PaymentRequestInitiationReq xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Sender><Id>%s</Id><Name>%s</Name><RandomValue>%s</RandomValue><Password>%s</Password></Sender><SettlementAmounts><SettlementAmounts><SettlementAccountCode>%s</SettlementAccountCode><SettlementAmountsDescription /><Amount>%s</Amount></SettlementAmounts></SettlementAmounts><SenderRequestNumber>%s</SenderRequestNumber><SenderInvoiceNumber>%s</SenderInvoiceNumber><ServiceCode>%s</ServiceCode><RequestInitiationDescription /><Currency>%s</Currency><IP>%s</IP><PaymentMechanism><Type>%s</Type><MechanismType>%s</MechanismType>';
        if ($PaymentMechanismType == "Channel") {
            //$string3 .= '<Channel><MobileNumber />'.$ChannelMobileNumber.'</MobileNumber><Email>%s</Email></Channel>';
            $string3 .= '<Channel><MobileNumber /><Email /></Channel>';
        } else {
            $string3 .= '<Channel />';
        }
        //<UserUniqueIdentifier>%s</UserUniqueIdentifier> will be before the closing to use Tokenization
        $string3 .= '</PaymentMechanism><ExpiryDate>%s</ExpiryDate><PaymentConfirmationUrl>%s</PaymentConfirmationUrl><PaymentConfirmationRedirectUrl>%s</PaymentConfirmationRedirectUrl></PaymentRequestInitiationReq>';
        //print '<pre>'; print_r($string3); exit;
        $str = sprintf($string3, $id, $biller_name, $random, $pass, $SettlementAccountCode,
            $amount, $SenderRequestNumber, $SenderInvoiceNumber, $ServiceCode, $Currency, $ip, $PaymentMechanismType, $MechanismType,
            $ExpiryDate, $PaymentConfirmationUrl, $PaymentConfirmationRedirectUrl);
        //$UserUniqueIdentifier);
        // print '<pre>'; print_r($str); exit;
        return $str;
    }

    /**
     * @param $plaintext
     * @param $orderNo
     * @param $macKey
     * @return array
     * @throws Exception
     */
    public function AESEncrypt($plaintext, $orderNo)
    {
        $blocksize = '16';
        $key = openssl_random_pseudo_bytes(32);
        if (mb_strlen($key, '8bit') !== 32) {
            throw new Exception("Needs a 256-bit key!");
        }
        $keyArr = unpack('C*', $key);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $ivArr = unpack('C*', $iv);
        $encryptedData = openssl_encrypt(
            $plaintext,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        $encryptedDataArr = unpack('C*', $encryptedData);
        $keyBytes = array();
        //clone the $keyArr to the keyBytes Array
        foreach ($keyArr as $key => $item) {
            $keyBytes[$key] = $item;
        }
        //clone the $ivArr to the keyBytes Array from index 32 to 48
        foreach ($ivArr as $key => $item) {
            $keyBytes[$key + 32] = $item;
        }
        $string = implode(array_map("chr", $keyBytes));
        $enc = implode(array_map("chr", $encryptedDataArr));
        $returned = //base64_encode($encryptedData);
            array(
                'encrypted' => base64_encode($enc),
                'randomSecret' => base64_encode($string),
            );
        file_put_contents($_SERVER['DOCUMENT_ROOT'] . '/pgw/logs/' . $orderNo . '.log', json_encode($returned));
        return $returned;
    }

    function HashSHA2_tibco($input)
    {
        $encoded = utf8_encode($input);
        $hash = hash('sha256', $encoded, true);
        return base64_encode($hash);

    }
    /**
     * @param $input
     * @return string
     */
    function HashSHA2($input)
    {
        $encoded = utf8_encode($input);
        $hash = hash('sha256', $encoded, true);
        $hashArr = unpack('C*', $hash);
        $str = array();
        foreach ($hashArr as $key => $item) {
            $str[] = $this->zeropad(dechex($item), 2);
        }
        $string = join("", $str);
        return $string;
    }

    /**
     * @param $num
     * @param $lim
     * @return string
     */
    function zeropad($num, $lim)
    {
        if (strlen($num) == 1)
            return '0' . $num;
        else
            return $num;
    }

    /**
     * @throws Exception
     */
    public function silentCall($requestObject, $senderRequestNumber)
    {
        $fileOpened = $_SERVER['DOCUMENT_ROOT'] . '/pgw/logs/' . $senderRequestNumber . '.log';
        $file = file_get_contents($fileOpened);
        $key = json_decode($file)->randomSecret;
        $xmlObject = $this->AESDecrypt($requestObject, $key);
        $x = array('key' => $key, 'file' => $fileOpened);
        file_put_contents($_SERVER['DOCUMENT_ROOT'] . '/pgw/check.txt', serialize($x));
        $xmlObject = preg_replace('/(<\?xml[^?]+?)utf-16/i', '$1utf-8', $xmlObject);
        $ob = simplexml_load_string($xmlObject);
        $encoded = json_encode($ob);
        $decoded = json_decode($encoded, true);
        //return serialize($decoded);
        return $decoded;
    }

    /**
     * @param $encryptedData
     * @param $passedKey
     * @return null|string
     */
    public function AESDecrypt($encryptedData, $passedKey)
    {
        $decryptedData = null;
        $keyArr = unpack('C*', openssl_random_pseudo_bytes(32));
        $ivArr = unpack('C*', openssl_random_pseudo_bytes(16));
        $keyBytes = unpack('C*', base64_decode($passedKey));
        //clone the $keyArr to the keyBytes Array
        for ($i = 1; $i < 33; $i++) {
            $keyArr[$i] = $keyBytes[$i];
        }
        $g = 0;
        for ($i = 33; $i < 49; $i++) {
            $ivArr[++$g] = $keyBytes[$i];
        }
        $key = implode(array_map("chr", $keyArr));
        $iv = implode(array_map("chr", $ivArr));
        $encryptedBytes = unpack('C*', base64_decode($encryptedData));
        $encryptedDataString = implode(array_map("chr", $encryptedBytes));
        $decryptedData = openssl_decrypt(
            $encryptedDataString,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
//        while ($msg = openssl_error_string())
//            echo $msg . "<br />\n";exit;
        return $decryptedData;
    }

    /**
     * @param $input
     * @return string
     */
    function HashSHA1($input)
    {
        $hash = sha1(mb_convert_encoding($input, "UTF-8"));
        return $hash;
    }
}

class PaymentRequestInitiationWebTransferReq
{
    public $Sender;
    public $EncryptedRequestObject;
    public $RandomSecret;
    public $DecryptedRequestObject;
    public $HasedRequestObject;

    /**
     * @return mixed
     */
    public function getSender()
    {
        return $this->Sender;
    }

    /**
     * @param mixed $Sender
     */
    public function setSender($Sender)
    {
        $this->Sender = $Sender;
    }

    /**
     * @return mixed
     */
    public function getEncryptedRequestObject()
    {
        return $this->EncryptedRequestObject;
    }

    /**
     * @param mixed $EncryptedRequestObject
     */
    public function setEncryptedRequestObject($EncryptedRequestObject)
    {
        $this->EncryptedRequestObject = $EncryptedRequestObject;
    }

    /**
     * @return mixed
     */
    public function getRandomSecret()
    {
        return $this->RandomSecret;
    }

    /**
     * @param mixed $RandomSecret
     */
    public function setRandomSecret($RandomSecret)
    {
        $this->RandomSecret = $RandomSecret;
    }

    /**
     * @return mixed
     */
    public function getDecryptedRequestObject()
    {
        return $this->DecryptedRequestObject;
    }

    /**
     * @param mixed $DecryptedRequestObject
     */
    public function setDecryptedRequestObject($DecryptedRequestObject)
    {
        $this->DecryptedRequestObject = $DecryptedRequestObject;
    }

    /**
     * @return mixed
     */
    public function getHasedRequestObject()
    {
        return $this->HasedRequestObject;
    }

    /**
     * @param mixed $HasedRequestObject
     */
    public function setHasedRequestObject($HasedRequestObject)
    {
        $this->HasedRequestObject = $HasedRequestObject;
    }
}

class Sender
{
    public $Id;
    public $Name;
    public $RandomValue;
    public $Password;

    /**
     * @return mixed
     */
    public function getId()
    {
        return $this->Id;
    }

    /**
     * @param mixed $Id
     */
    public function setId($Id)
    {
        $this->Id = $Id;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->Name;
    }

    /**
     * @param mixed $Name
     */
    public function setName($Name)
    {
        $this->Name = $Name;
    }

    /**
     * @return mixed
     */
    public function getRandomValue()
    {
        return $this->RandomValue;
    }

    /**
     * @param mixed $RandomValue
     */
    public function setRandomValue($RandomValue)
    {
        $this->RandomValue = $RandomValue;
    }

    /**
     * @return mixed
     */
    public function getPassword()
    {
        return $this->Password;
    }

    /**
     * @param mixed $Password
     */
    public function setPassword($Password)
    {
        $this->Password = $Password;
    }
}

class PaymentConfirmationRequest
{
    public $Sender;
    public $SenderRequestNumber;
    public $PaymentRequestNumber;
    public $PaymentRequestTotalAmount;
    public $CollectionFeesAmount;
    public $CustomerAuthorizationAmount;
    public $AuthorizationCode;
    public $TransactionNumber;
    public $AuthorizingMechanism;
    public $AuthorizingInstitution;
    public $AuthoriztionDateTime;
    public $ReconciliationDate;

    /**
     * @return mixed
     */
    public function getSender()
    {
        return $this->Sender;
    }

    /**
     * @param mixed $Sender
     */
    public function setSender($Sender)
    {
        $this->Sender = $Sender;
    }

    /**
     * @return mixed
     */
    public function getSenderRequestNumber()
    {
        return $this->SenderRequestNumber;
    }

    /**
     * @param mixed $SenderRequestNumber
     */
    public function setSenderRequestNumber($SenderRequestNumber)
    {
        $this->SenderRequestNumber = $SenderRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getPaymentRequestNumber()
    {
        return $this->PaymentRequestNumber;
    }

    /**
     * @param mixed $PaymentRequestNumber
     */
    public function setPaymentRequestNumber($PaymentRequestNumber)
    {
        $this->PaymentRequestNumber = $PaymentRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getPaymentRequestTotalAmount()
    {
        return $this->PaymentRequestTotalAmount;
    }

    /**
     * @param mixed $PaymentRequestTotalAmount
     */
    public function setPaymentRequestTotalAmount($PaymentRequestTotalAmount)
    {
        $this->PaymentRequestTotalAmount = $PaymentRequestTotalAmount;
    }

    /**
     * @return mixed
     */
    public function getCollectionFeesAmount()
    {
        return $this->CollectionFeesAmount;
    }

    /**
     * @param mixed $CollectionFeesAmount
     */
    public function setCollectionFeesAmount($CollectionFeesAmount)
    {
        $this->CollectionFeesAmount = $CollectionFeesAmount;
    }

    /**
     * @return mixed
     */
    public function getCustomerAuthorizationAmount()
    {
        return $this->CustomerAuthorizationAmount;
    }

    /**
     * @param mixed $CustomerAuthorizationAmount
     */
    public function setCustomerAuthorizationAmount($CustomerAuthorizationAmount)
    {
        $this->CustomerAuthorizationAmount = $CustomerAuthorizationAmount;
    }

    /**
     * @return mixed
     */
    public function getAuthorizationCode()
    {
        return $this->AuthorizationCode;
    }

    /**
     * @param mixed $AuthorizationCode
     */
    public function setAuthorizationCode($AuthorizationCode)
    {
        $this->AuthorizationCode = $AuthorizationCode;
    }

    /**
     * @return mixed
     */
    public function getTransactionNumber()
    {
        return $this->TransactionNumber;
    }

    /**
     * @param mixed $TransactionNumber
     */
    public function setTransactionNumber($TransactionNumber)
    {
        $this->TransactionNumber = $TransactionNumber;
    }

    /**
     * @return mixed
     */
    public function getAuthorizingMechanism()
    {
        return $this->AuthorizingMechanism;
    }

    /**
     * @param mixed $AuthorizingMechanism
     */
    public function setAuthorizingMechanism($AuthorizingMechanism)
    {
        $this->AuthorizingMechanism = $AuthorizingMechanism;
    }

    /**
     * @return mixed
     */
    public function getAuthorizingInstitution()
    {
        return $this->AuthorizingInstitution;
    }

    /**
     * @param mixed $AuthorizingInstitution
     */
    public function setAuthorizingInstitution($AuthorizingInstitution)
    {
        $this->AuthorizingInstitution = $AuthorizingInstitution;
    }

    /**
     * @return mixed
     */
    public function getAuthoriztionDateTime()
    {
        return $this->AuthoriztionDateTime;
    }

    /**
     * @param mixed $AuthoriztionDateTime
     */
    public function setAuthoriztionDateTime($AuthoriztionDateTime)
    {
        $this->AuthoriztionDateTime = $AuthoriztionDateTime;
    }

    /**
     * @return mixed
     */
    public function getReconciliationDate()
    {
        return $this->ReconciliationDate;
    }

    /**
     * @param mixed $ReconciliationDate
     */
    public function setReconciliationDate($ReconciliationDate)
    {
        $this->ReconciliationDate = $ReconciliationDate;
    }
}

class PaymentRequestStatus
{
    public $Code;
    public $Name;

    /**
     * @return mixed
     */
    public function getCode()
    {
        return $this->Code;
    }

    /**
     * @param mixed $Code
     */
    public function setCode($Code)
    {
        $this->Code = $Code;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->Name;
    }

    /**
     * @param mixed $Name
     */
    public function setName($Name)
    {
        $this->Name = $Name;
    }
}

class SettlementAmounts
{
    public $SettlementAccountCode;
    public $SettlementAmountsDescription;
    public $Amount;

    /**
     * @return mixed
     */
    public function getSettlementAccountCode()
    {
        return $this->SettlementAccountCode;
    }

    /**
     * @param mixed $SettlementAccountCode
     */
    public function setSettlementAccountCode($SettlementAccountCode)
    {
        $this->SettlementAccountCode = $SettlementAccountCode;
    }

    /**
     * @return mixed
     */
    public function getSettlementAmountsDescription()
    {
        return $this->SettlementAmountsDescription;
    }

    /**
     * @param mixed $SettlementAmountsDescription
     */
    public function setSettlementAmountsDescription($SettlementAmountsDescription)
    {
        $this->SettlementAmountsDescription = $SettlementAmountsDescription;
    }

    /**
     * @return mixed
     */
    public function getAmount()
    {
        return $this->Amount;
    }

    /**
     * @param mixed $Amount
     */
    public function setAmount($Amount)
    {
        $this->Amount = $Amount;
    }
}

class PaymentRequestInitiationReq
{
    public $Sender;
    public $SettlementAmounts;                                //
    public $SenderRequestNumber;
    public $SenderInvoiceNumber;
    public $ServiceCode;
    public $RequestInitiationDescription;
    public $Currency;
    public $IP;
    public $PaymentMechanism;
    public $ExpiryDate;
    public $PaymentConfirmationUrl;
    public $PaymentConfirmationRedirectUrl;
    public $UserUniqueIdentifier;

    /**
     * @return mixed
     */
    public function getSender()
    {
        return $this->Sender;
    }

    /**
     * @param mixed $Sender
     */
    public function setSender($Sender)
    {
        $this->Sender = $Sender;
    }

    /**
     * @return mixed
     */
    public function getSettlementAmounts()
    {
        return $this->SettlementAmounts;
    }

    /**
     * @param mixed $SettlementAmounts
     */
    public function setSettlementAmounts($SettlementAmounts)
    {
        $this->SettlementAmounts = $SettlementAmounts;
    }

    /**
     * @return mixed
     */
    public function getSenderRequestNumber()
    {
        return $this->SenderRequestNumber;
    }

    /**
     * @param mixed $SenderRequestNumber
     */
    public function setSenderRequestNumber($SenderRequestNumber)
    {
        $this->SenderRequestNumber = $SenderRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getSenderInvoiceNumber()
    {
        return $this->SenderInvoiceNumber;
    }

    /**
     * @param mixed $SenderInvoiceNumber
     */
    public function setSenderInvoiceNumber($SenderInvoiceNumber)
    {
        $this->SenderInvoiceNumber = $SenderInvoiceNumber;
    }

    /**
     * @return mixed
     */
    public function getServiceCode()
    {
        return $this->ServiceCode;
    }

    /**
     * @param mixed $ServiceCode
     */
    public function setServiceCode($ServiceCode)
    {
        $this->ServiceCode = $ServiceCode;
    }

    /**
     * @return mixed
     */
    public function getRequestInitiationDescription()
    {
        return $this->RequestInitiationDescription;
    }

    /**
     * @param mixed $RequestInitiationDescription
     */
    public function setRequestInitiationDescription($RequestInitiationDescription)
    {
        $this->RequestInitiationDescription = $RequestInitiationDescription;
    }

    /**
     * @return mixed
     */
    public function getCurrency()
    {
        return $this->Currency;
    }

    /**
     * @param mixed $Currency
     */
    public function setCurrency($Currency)
    {
        $this->Currency = $Currency;
    }

    /**
     * @return mixed
     */
    public function getIP()
    {
        return $this->IP;
    }

    /**
     * @param mixed $IP
     */
    public function setIP($IP)
    {
        $this->IP = $IP;
    }

    /**
     * @return mixed
     */
    public function getPaymentMechanism()
    {
        return $this->PaymentMechanism;
    }

    /**
     * @param $PaymentMechanism
     */
    public function setPaymentMechanism($PaymentMechanism)
    {
        $this->PaymentMechanism = $PaymentMechanism;
    }

    /**
     * @return mixed
     */
    public function getExpiryDate()
    {
        return $this->ExpiryDate;
    }

    /**
     * @param mixed $ExpiryDate
     */
    public function setExpiryDate($ExpiryDate)
    {
        $this->ExpiryDate = $ExpiryDate;
    }

    /**
     * @return mixed
     */
    public function getPaymentConfirmationUrl()
    {
        return $this->PaymentConfirmationUrl;
    }

    /**
     * @param mixed $PaymentConfirmationUrl
     */
    public function setPaymentConfirmationUrl($PaymentConfirmationUrl)
    {
        $this->PaymentConfirmationUrl = $PaymentConfirmationUrl;
    }

    /**
     * @return mixed
     */
    public function getPaymentConfirmationRedirectUrl()
    {
        return $this->PaymentConfirmationRedirectUrl;
    }

    /**
     * @param mixed $PaymentConfirmationRedirectUrl
     */
    public function setPaymentConfirmationRedirectUrl($PaymentConfirmationRedirectUrl)
    {
        $this->PaymentConfirmationRedirectUrl = $PaymentConfirmationRedirectUrl;
    }

    /**
     * @return mixed
     */
    public function getUserUniqueIdentifier()
    {
        return $this->UserUniqueIdentifier;
    }

    /**
     * @param $UserUniqueIdentifier
     */
    public function setUserUniqueIdentifier($UserUniqueIdentifier)
    {
        $this->UserUniqueIdentifier = $UserUniqueIdentifier;
    }
}

class PaymentRequestInitiationRes
{
    public $Sender;
    public $OriginalSenderRequestNumber;
    public $PaymentRequestNumber;
    public $Currency;
    public $OriginalPaymentRequestAmount;
    public $CollectionFeesAmount;
    public $TotalAuthorizationAmount;
    public $Session3DESKey;
    public $ResponseCode;
    public $ResponseMessage;

    /**
     * @return mixed
     */
    public function getSender()
    {
        return $this->Sender;
    }

    /**
     * @param mixed $Sender
     */
    public function setSender($Sender)
    {
        $this->Sender = $Sender;
    }

    /**
     * @return mixed
     */
    public function getOriginalSenderRequestNumber()
    {
        return $this->OriginalSenderRequestNumber;
    }

    /**
     * @param mixed $OriginalSenderRequestNumber
     */
    public function setOriginalSenderRequestNumber($OriginalSenderRequestNumber)
    {
        $this->OriginalSenderRequestNumber = $OriginalSenderRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getPaymentRequestNumber()
    {
        return $this->PaymentRequestNumber;
    }

    /**
     * @param mixed $PaymentRequestNumber
     */
    public function setPaymentRequestNumber($PaymentRequestNumber)
    {
        $this->PaymentRequestNumber = $PaymentRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getCurrency()
    {
        return $this->Currency;
    }

    /**
     * @param mixed $Currency
     */
    public function setCurrency($Currency)
    {
        $this->Currency = $Currency;
    }

    /**
     * @return mixed
     */
    public function getOriginalPaymentRequestAmount()
    {
        return $this->OriginalPaymentRequestAmount;
    }

    /**
     * @param mixed $OriginalPaymentRequestAmount
     */
    public function setOriginalPaymentRequestAmount($OriginalPaymentRequestAmount)
    {
        $this->OriginalPaymentRequestAmount = $OriginalPaymentRequestAmount;
    }

    /**
     * @return mixed
     */
    public function getCollectionFeesAmount()
    {
        return $this->CollectionFeesAmount;
    }

    /**
     * @param mixed $CollectionFeesAmount
     */
    public function setCollectionFeesAmount($CollectionFeesAmount)
    {
        $this->CollectionFeesAmount = $CollectionFeesAmount;
    }

    /**
     * @return mixed
     */
    public function getTotalAuthorizationAmount()
    {
        return $this->TotalAuthorizationAmount;
    }

    /**
     * @param mixed $TotalAuthorizationAmount
     */
    public function setTotalAuthorizationAmount($TotalAuthorizationAmount)
    {
        $this->TotalAuthorizationAmount = $TotalAuthorizationAmount;
    }

    /**
     * @return mixed
     */
    public function getSession3DESKey()
    {
        return $this->Session3DESKey;
    }

    /**
     * @param mixed $Session3DESKey
     */
    public function setSession3DESKey($Session3DESKey)
    {
        $this->Session3DESKey = $Session3DESKey;
    }

    /**
     * @return mixed
     */
    public function getResponseCode()
    {
        return $this->ResponseCode;
    }

    /**
     * @param mixed $ResponseCode
     */
    public function setResponseCode($ResponseCode)
    {
        $this->ResponseCode = $ResponseCode;
    }

    /**
     * @return mixed
     */
    public function getResponseMessage()
    {
        return $this->ResponseMessage;
    }

    /**
     * @param mixed $ResponseMessage
     */
    public function setResponseMessage($ResponseMessage)
    {
        $this->ResponseMessage = $ResponseMessage;
    }
}

class PaymentRequestConfirmationReqSilentCall
{
    public $SenderID;
    public $SenderRequestNumber;
    public $IsConfirmed;
    public $RandomSecret;
    public $RequestObject;

    /**
     * @return mixed
     */
    public function getSenderID()
    {
        return $this->SenderID;
    }

    /**
     * @param mixed $SenderID
     */
    public function setSenderID($SenderID)
    {
        $this->SenderID = $SenderID;
    }

    /**
     * @return mixed
     */
    public function getSenderRequestNumber()
    {
        return $this->SenderRequestNumber;
    }

    /**
     * @param mixed $SenderRequestNumber
     */
    public function setSenderRequestNumber($SenderRequestNumber)
    {
        $this->SenderRequestNumber = $SenderRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getisConfirmed()
    {
        return $this->IsConfirmed;
    }

    /**
     * @param mixed $IsConfirmed
     */
    public function setIsConfirmed($IsConfirmed)
    {
        $this->IsConfirmed = $IsConfirmed;
    }

    /**
     * @return mixed
     */
    public function getRandomSecret()
    {
        return $this->RandomSecret;
    }

    /**
     * @param mixed $RandomSecret
     */
    public function setRandomSecret($RandomSecret)
    {
        $this->RandomSecret = $RandomSecret;
    }

    /**
     * @return mixed
     */
    public function getRequestObject()
    {
        return $this->RequestObject;
    }

    /**
     * @param mixed $RequestObject
     */
    public function setRequestObject($RequestObject)
    {
        $this->RequestObject = $RequestObject;
    }
}

class PaymentStatusInquiryReq
{
    private $Sender;
    private $SenderRequestNumber;

    /**
     * @return mixed
     */
    public function getSender()
    {
        return $this->Sender;
    }

    /**
     * @param mixed $Sender
     */
    public function setSender($Sender)
    {
        $this->Sender = $Sender;
    }

    /**
     * @return mixed
     */
    public function getSenderRequestNumber()
    {
        return $this->SenderRequestNumber;
    }

    /**
     * @param mixed $SenderRequestNumber
     */
    public function setSenderRequestNumber($SenderRequestNumber)
    {
        $this->SenderRequestNumber = $SenderRequestNumber;
    }
}

class PaymentStatusInquiryRes
{
    public $PaymentRequestStatusObject;

    /**
     * @return mixed
     */
    public function getPaymentRequestStatusObject()
    {
        return $this->PaymentRequestStatusObject;
    }

    /**
     * @param mixed $PaymentRequestStatusObject
     */
    public function setPaymentRequestStatusObject($PaymentRequestStatusObject)
    {
        $this->PaymentRequestStatusObject = $PaymentRequestStatusObject;
    }
}

class PaymentStatusInquiryRequestCall
{
    public $SenderID;
    public $RandomSecret;
    public $PaymentStatusInquiryRequestObject;
    public $HasedPaymentStatusInquiryRequestObject;
    public $RequestObject;

    /**
     * @return mixed
     */
    public function getSenderID()
    {
        return $this->SenderID;
    }

    /**
     * @param mixed $SenderID
     */
    public function setSenderID($SenderID)
    {
        $this->SenderID = $SenderID;
    }

    /**
     * @return mixed
     */
    public function getRandomSecret()
    {
        return $this->RandomSecret;
    }

    /**
     * @param mixed $RandomSecret
     */
    public function setRandomSecret($RandomSecret)
    {
        $this->RandomSecret = $RandomSecret;
    }

    /**
     * @return mixed
     */
    public function getPaymentStatusInquiryRequestObject()
    {
        return $this->PaymentStatusInquiryRequestObject;
    }

    /**
     * @param mixed $PaymentStatusInquiryRequestObject
     */
    public function setPaymentStatusInquiryRequestObject($PaymentStatusInquiryRequestObject)
    {
        $this->PaymentStatusInquiryRequestObject = $PaymentStatusInquiryRequestObject;
    }

    /**
     * @return mixed
     */
    public function getHasedPaymentStatusInquiryRequestObject()
    {
        return $this->HasedPaymentStatusInquiryRequestObject;
    }

    /**
     * @param mixed $HasedPaymentStatusInquiryRequestObject
     */
    public function setHasedPaymentStatusInquiryRequestObject($HasedPaymentStatusInquiryRequestObject)
    {
        $this->HasedPaymentStatusInquiryRequestObject = $HasedPaymentStatusInquiryRequestObject;
    }

    /**
     * @return mixed
     */
    public function getRequestObject()
    {
        return $this->RequestObject;
    }

    /**
     * @param mixed $RequestObject
     */
    public function setRequestObject($RequestObject)
    {
        $this->RequestObject = $RequestObject;
    }
}

class PaymentConfirmationResponse
{
    public $Sender;
    public $OriginalSenderRequestNumber;
    public $AuthorizerRequestNumber;
    public $ResponseCode;
    public $ResponseMessage;
    public $ConfirmationRedirectURL;
    public $RequestObjectSignature;
    public $PaymentRequestConfirmationReqSilentCall;

    /**
     * @return mixed
     */
    public function getSender()
    {
        return $this->Sender;
    }

    /**
     * @param mixed $Sender
     */
    public function setSender($Sender)
    {
        $this->Sender = $Sender;
    }

    /**
     * @return mixed
     */
    public function getOriginalSenderRequestNumber()
    {
        return $this->OriginalSenderRequestNumber;
    }

    /**
     * @param mixed $OriginalSenderRequestNumber
     */
    public function setOriginalSenderRequestNumber($OriginalSenderRequestNumber)
    {
        $this->OriginalSenderRequestNumber = $OriginalSenderRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getAuthorizerRequestNumber()
    {
        return $this->AuthorizerRequestNumber;
    }

    /**
     * @param mixed $AuthorizerRequestNumber
     */
    public function setAuthorizerRequestNumber($AuthorizerRequestNumber)
    {
        $this->AuthorizerRequestNumber = $AuthorizerRequestNumber;
    }

    /**
     * @return mixed
     */
    public function getResponseCode()
    {
        return $this->ResponseCode;
    }

    /**
     * @param mixed $ResponseCode
     */
    public function setResponseCode($ResponseCode)
    {
        $this->ResponseCode = $ResponseCode;
    }

    /**
     * @return mixed
     */
    public function getResponseMessage()
    {
        return $this->ResponseMessage;
    }

    /**
     * @param mixed $ResponseMessage
     */
    public function setResponseMessage($ResponseMessage)
    {
        $this->ResponseMessage = $ResponseMessage;
    }

    /**
     * @return mixed
     */
    public function getConfirmationRedirectURL()
    {
        return $this->ConfirmationRedirectURL;
    }

    /**
     * @param mixed $ConfirmationRedirectURL
     */
    public function setConfirmationRedirectURL($ConfirmationRedirectURL)
    {
        $this->ConfirmationRedirectURL = $ConfirmationRedirectURL;
    }

    /**
     * @return mixed
     */
    public function getRequestObjectSignature()
    {
        return $this->RequestObjectSignature;
    }

    /**
     * @param mixed $RequestObjectSignature
     */
    public function setRequestObjectSignature($RequestObjectSignature)
    {
        $this->RequestObjectSignature = $RequestObjectSignature;
    }

    /**
     * @return mixed
     */
    public function getPaymentRequestConfirmationReqSilentCall()
    {
        return $this->PaymentRequestConfirmationReqSilentCall;
    }

    /**
     * @param mixed $PaymentRequestConfirmationReqSilentCall
     */
    public function setPaymentRequestConfirmationReqSilentCall($PaymentRequestConfirmationReqSilentCall)
    {
        $this->PaymentRequestConfirmationReqSilentCall = $PaymentRequestConfirmationReqSilentCall;
    }
}

class PaymentMechanismChannel
{
    public $MobileNumber;
    public $Email;

    /**
     * @return mixed
     */
    public function getMobileNumber()
    {
        return $this->MobileNumber;
    }

    /**
     * @param mixed $MobileNumber
     */
    public function setMobileNumber($MobileNumber)
    {
        $this->MobileNumber = $MobileNumber;
    }

    /**
     * @return mixed
     */
    public function getEmail()
    {
        return $this->Email;
    }

    /**
     * @param mixed $Email
     */
    public function setEmail($Email)
    {
        $this->Email = $Email;
    }
}

class PaymentMechanism
{
    const NotSet = '0';
    const Card = '1';
    const Channel = '2';
    public $Type;
    public $MechanismType;
    public $Channel;

    /**
     * @return mixed
     */
    public function getType()
    {
        return $this->Type;
    }

    /**
     * @param mixed $Type
     */
    public function setType($Type)
    {
        $this->Type = $Type;
    }

    /**
     * @return mixed
     */
    public function getMechanismType()
    {
        return $this->MechanismType;
    }

    /**
     * @param mixed $MechanismType
     */
    public function setMechanismType($MechanismType)
    {
        $this->MechanismType = $MechanismType;
    }

    /**
     * @return mixed
     */
    public function getChannel()
    {
        return $this->Channel;
    }

    /**
     * @param mixed $Channel
     */
    public function setChannel($Channel)
    {
        $this->Channel = $Channel;
    }
}

?>
