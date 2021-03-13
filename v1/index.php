<?php

/**
 * Class to handle all riutes
 *
 * @author Saugat Timilsina
 */

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Apikey'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Apikey'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password'));

            $response = array();

            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');

            // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createUser($name, $email, $password);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['name'] = $user['name'];
                    $response['email'] = $user['email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }

            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */

$app -> post('/post-feed','authenticate',function () use($app){

    global $user_id;
    // verifyRequiredParams(array('file'));
    $uploadDirectoryLink = 'https://android.saugatimilsina.com.np/assets/posts/';
   $response = array();
    if(isset($_FILES['file'])){
       $fileName = $_FILES['file']['name'];
    $fileSize = $_FILES['file']['size'];
    $fileTmpName = $_FILES['file']['tmp_name'];
    $fileType = $_FILES['file']['type'];

    $tmpo = explode('.', $fileName);
    $fileExtension = end($tmpo);
    $path_parts = pathinfo($_FILES["file"]["name"]);
    $filename = $path_parts['filename'] . '_' . time() . '_'.$user_id. '.' . $path_parts['extension']  ;

    $year = date("Y");
    $month = date("m");
    $short_dir = $year . "/" . $month;
    $imageLink ="https://android.saugatimilsina.com.np/assets/posts/" . $short_dir . "/" . $filename;

    $post_image = $imageLink;
    $post_desc = null;
  
    if($app->request->post('post_desc') != null){
        $post_desc = $app->request->post('post_desc');
    }
     

  
   

    $db = new DbHandler();

    if($db->uploadProfilePic($user_id,$post_desc,$fileSize, $fileTmpName, $fileType, $fileExtension , $filename ,$imageLink))
    {
        $response["error"] = false;
        $response["message"] = "Post successfully created";
             echoRespnse(201, $response);
      
        
    }else
    {
        $response["error"] = true;
        $response["message"] = "Post creation failed! Try again!";
             echoRespnse(300, $response);
      

    }   
        
    }
    else{
         $response["error"] = true;
        $response["message"] = "Please profile image to post!";
             echoRespnse(400, $response);
    }
  



});

$app -> post('/get-all-feed', 'authenticate', function () use ($app){
    global $user_id;
    $response = array();

    $db = new DbHandler();
    $response["feed"] = $db->getAllFeed($user_id);
    $response["error"] = false;
    $response["message"] = "Post successfully created";
    echoRespnse(200, $response);

});

$app -> post('/get-my-feed', 'authenticate', function () use ($app){
    global $user_id;
    $response = array();

    $db = new DbHandler();
    $response["feed"] = $db->getMyFeed($user_id);
    $response["error"] = false;
    $response["message"] = "SuccessFull";
    echoRespnse(200, $response);

});

$app -> post('/follow', 'authenticate', function () use ($app){
    global $user_id;
    $response = array();
    verifyRequiredParams(array('following_id'));

    $following_id = $app->request->post('following_id');
    $db = new DbHandler();
 $res =   $db->followUser($user_id, $following_id);
 if($res == USER_CREATED_SUCCESSFULLY){
    $response["error"] = false;
    $response["message"] = "Followed successfully";
    echoRespnse(201, $response);
 }
 else if($res == 9){
    $response["error"] = true;
    $response["message"] = "Already following";
    echoRespnse(400, $response);
 }

});

$app -> post('/unfollow', 'authenticate', function () use ($app){
    global $user_id;
    $response = array();
    verifyRequiredParams(array('following_id'));

    $following_id = $app->request->post('following_id');
    $db = new DbHandler();
 $res =   $db->unFollowUser($user_id, $following_id);
 if($res == USER_CREATED_SUCCESSFULLY){
    $response["error"] = false;
    $response["message"] = "Unfollowed successfully";
    echoRespnse(204, $response);
 }
 else if($res == 9){
    $response["error"] = true;
    $response["message"] = "Not Following Already";
    echoRespnse(400, $response);
 }

});

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>