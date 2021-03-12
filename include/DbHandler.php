<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ravi Tamada
 * @link URL Tutorial link
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }




   

    /* ------------- `users` table method ------------------ */

    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($name, $email, $password) {


        require_once 'PassHash.php';
        $response = array();

        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO users(name, email, password_hash, api_key, status) values(?, ?, ?, ?, 1)");
            $stmt->bind_param("ssss", $name, $email, $password_hash, $api_key);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }



     /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function updateUser($name, $email, $password) {
        require_once 'PassHash.php';
        $response = array();

        // First check if user already existed in db
       
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("Update users set name = ?, WHERE email = ?");
            $stmt->bind_param("ss", $name, $email);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return TRUE;
            } else {
                // Failed to create user
                return FALSE;
            }
        

       
    }

    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the email
            return FALSE;
        }
    }

    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE email = ? ");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT name, email, api_key, status, created_at FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($name, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
            $user["name"] = $name;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }


     /**
     * Fetching user is_staff
     * @param String $user_id user id primary key in user table
     */
    public function getUserIsStaffById($user_id) {
        $stmt = $this->conn->prepare("SELECT is_staff FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($is_staff);
            $stmt->fetch();
            $stmt->close();
            return $is_staff;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }




       /* ------------- `users` table method ------------------ */

    /**
     * Creating new book record

     * @param String $email User login email id
     * @param String $password User login password
     */
    public function addBook($title, $author, $stock, $price, $cover_image) {


       
        $response = array();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO books(title, author, stock_quanity, price, cover_image) values(?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $title, $author, $stock, $price, $cover_image);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        

        return $response;
    }


  /**
     * Get all feed from database
     */

    public function getAllFeed($user_id)
    {
        $data = array();
        $data_full = array();
       
        $stmt = $this->conn->prepare("SELECT * FROM `feed` ORDER BY `feed`.`time` DESC");
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($id, $user, $time, $post_desc, $post_image);
          // $fileLink = array();
            // $fileLink = explode(',', $dataLink);
            while ($stmt->fetch()) { 
                $feed = array();
                $feed["id"] = $id;
                $feed["user"] = $user;
                $feed["time"] = $time;
                $feed["post_desc"] = $post_desc;
                $feed["post_image"] = $post_image;
                // $user_profile = $this -> getUserImageNameFromID($feed["user"]);
                // $feed["profile_image"] =  $user_profile["pp"];
                // $feed["user_name"] = $user_profile["name"];
                array_push($data, $feed);
            } 

            $stmt->close();
         
        } else {
            return NULL;
        }

        foreach($data as $d){
                $feed = array();
                $feed["id"]=    $d["id"] ;
                $feed["time"]=   $d["time"];
                $feed["post_desc"]  =    $d["post_desc"];
                $feed["post_image"] =   $d["post_image"]; 
                $user_profile = $this -> getUserImageNameFromID($d["user"]);
                $feed["profile_image"] =  $user_profile["pp"];
                $feed["user_name"] = $user_profile["name"];
                $feed["user_id"] = $user_profile["id"];
                $feed["following"] = $this -> checkFollowing($user_id,$d["user"]);
                array_push($data_full, $feed);
        }
        return $data_full;
    }
    
      public function getMyFeed($user_id)
    {
        $data = array();
        $data_full = array();
       
        $stmt = $this->conn->prepare("SELECT * FROM `feed` WHERE user = ? ORDER BY `feed`.`time` DESC");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($id, $user, $time, $post_desc, $post_image);
          // $fileLink = array();
            // $fileLink = explode(',', $dataLink);
            while ($stmt->fetch()) { 
                $feed = array();
                $feed["id"] = $id;
                $feed["user"] = $user;
                $feed["time"] = $time;
                $feed["post_desc"] = $post_desc;
                $feed["post_image"] = $post_image;
                // $user_profile = $this -> getUserImageNameFromID($feed["user"]);
                // $feed["profile_image"] =  $user_profile["pp"];
                // $feed["user_name"] = $user_profile["name"];
                array_push($data, $feed);
            } 

            $stmt->close();
              return $data;
         
        } else {
            return NULL;
        }

       
      
    }

    public function getUserImageNameFromID($id){
        $stmt = $this->conn->prepare("SELECT name, profile_pic FROM users WHERE id = ?");
        $stmt->bind_param("i", $id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($name, $pp);
            $stmt->fetch();
            $stmt->close();
            $result = array();
            $result["id"] = $id;
            $result["name"] = $name;
            $result["pp"] = $pp;
            return $result;

        } else {
            return NULL;
        }

    }


    public function checkFollowing($user_id , $following_id){
        $stmt = $this->conn->prepare("SELECT id FROM user_following WHERE user_id = ? and following_id = ?");
        $stmt->bind_param("ii", $user_id, $following_id);
        if ($stmt->execute()) {
            $stmt->bind_result($id);
            $stmt->fetch();
            $stmt->close();
            if($id == null)
            return false;
            else
            return true;
        } 

    }

    public function followUser($user_id , $following_id){
             // insert query
     
             if(!$this-> checkFollowing($user_id , $following_id)){
                $stmt = $this->conn->prepare("INSERT INTO `user_following` ( `user_id`, `following_id`) VALUES (?, ?)");
                $stmt->bind_param("ii",$user_id , $following_id); 
                $result = $stmt->execute();
            
                $stmt->close();
                // Check for successful insertion
                if ($result) {
                    // User successfully inserted
                    return USER_CREATED_SUCCESSFULLY;
                } else {
                    // Failed to create user
                    return $this->conn->error();
                }
            

             }
             else{
                return 9;
             }
  
    }

    public function unFollowUser($user_id , $following_id){
        // insert query

        if($this-> checkFollowing($user_id , $following_id)){

           $stmt = $this->conn->prepare("DELETE FROM `user_following` WHERE  `user_id` = ? AND  `following_id` = ?");
           $stmt->bind_param("ii",$user_id , $following_id); 
           $result = $stmt->execute();
       
           $stmt->close();
           // Check for successful insertion
           if ($result) {
               // User successfully inserted
               return USER_CREATED_SUCCESSFULLY;
           } else {
               // Failed to create user
               return $this->conn->error();
           }
       

        }
        else{
           return 9;
        }

}


public function createPost($user, $post_image, $post_dec){

    $stmt = $this->conn->prepare("INSERT INTO feed(user, post_desc, post_image) values(?, ?, ?)");
    $stmt->bind_param("iss", $user, $post_dec, $post_image);
    $result = $stmt->execute();
    $stmt->close();
      return $result;


}
public function uploadProfilePic($user_id,$post_dec, $fileSize, $fileTmpName, $fileType, $fileExtension ,$filename , $imageLink)
{
    $currentDir = getcwd();
    $errors = [];
    $uploadDirectory ="/". $this->getDirectory();
    $uploadPath = $currentDir . $uploadDirectory . basename($filename);
    $fileExtensions = ['jpeg', 'jpg', 'png', 'JPG', 'PNG', 'JPEG'];

    if (!in_array($fileExtension, $fileExtensions)) {
        return 2;
    } elseif ($fileSize > 14256000) {
        return 3;
    } else {

        if (file_exists($uploadPath)) {

            unlink($uploadPath);


        }

        $didUpload = move_uploaded_file($fileTmpName, $uploadPath);
        if ($didUpload) {
            $this->createPost($user_id , $imageLink, $post_dec);
            return 1;
        } else {
            return 4;
        }


    }


}

function getDirectory()
{
    $dir = "../../assets/posts/";

    $year = date("Y");
    $month = date("m");
    $yearDirectory = $dir . $year;
    $folderDirectory = $dir . $year . "/" . $month ."/";
    if (file_exists($yearDirectory)) {
        if (file_exists($folderDirectory) == false) {
            mkdir($folderDirectory, 0777);
            return $folderDirectory ;
        }
    } else {
        mkdir($yearDirectory, 0777);
        mkdir($folderDirectory, 0777);
        return $folderDirectory ;
    }
    return $folderDirectory ;
}



}

?>
