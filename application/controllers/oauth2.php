<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

require APPPATH.'/libraries/REST_Controller.php';

/**
* 
*/
//class Oauth2 extends CI_Controller
class Oauth2 extends REST_Controller
{

    public function __construct()
    {
        parent::__construct();

        $this->load->library('session');
        $this->load->helper(array('url', 'form'));

        // Initiate the request handler which deals with $_GET, $_POST, etc
        $request = new League\OAuth2\Server\Util\Request();

        // Initiate a new database connection
        $this->db = new League\OAuth2\Server\Storage\PDO\Db('mysql://root@localhost/oauth2');

        // Create the auth server, the three parameters passed are references to the storage models
        $this->authserver = new League\OAuth2\Server\Authorization(
            new League\OAuth2\Server\Storage\PDO\Client($db),
            new League\OAuth2\Server\Storage\PDO\Session($db),
            new League\OAuth2\Server\Storage\PDO\Scope($db)
        );

        // Set the scope delimeter to contain commas. e.g. 'scope1,scope2,scope3'
        $this->authserver->setScopeDelimeter(',');

        // Throw an error if the scope paramater is not set (makes requests more explicit)
        $this->authserver->requireScopeParam(true);

        // Set the oauth token lifetime (in seconds)
        $this->authserver->setAccessTokenTTL(94608000); //is 3 years enough lol?

        // Enable the authorization code grant type
        $this->authserver->addGrantType(new League\OAuth2\Server\Grant\AuthCode($this->authserver));

    }

    public function index_GET()
    {
        try {

            // Tell the auth server to check the required parameters are in the query string
            $params = $this->authserver->getGrantType('authorization_code')->checkAuthoriseParams();

            $this->session->set_userdata('client_id', $params['client_id']);
            $this->session->set_userdata('client_details', $params['client_details']);
            $this->session->set_userdata('redirect_uri', $params['redirect_uri']);
            $this->session->set_userdata('response_type', $params['response_type']);
            $this->session->set_userdata('scopes', $params['scopes']);

            // Redirect the user to the sign-in route
            redirect('/oauth2/signin');

        } catch (Oauth2\Exception\ClientException $e) {
            // Throw an error  which says what the problem is with the auth params
            $this->response(array('error' => $e->getMessage()), 400);

        } catch (Exception $e) {
            // Throw an error  which has caught a non-library specific error
            $this->response(array('error' => $e->getMessage()), 400);
        }
    }


    public function signin_GET()
    {
        // Retrieve the auth params from the user's session
        $params['client_id'] = $this->session->userdata('client_id');
        $params['client_details'] = $this->session->userdata('client_details');
        $params['redirect_uri'] = $this->session->userdata('redirect_uri');
        $params['response_type'] = $this->session->userdata('response_type');
        $params['scopes'] = $this->session->userdata('scopes');

        // Check that the auth params are all present
        foreach ($params as $key=>$value) {
            if ($value == null) {
                // Throw an error because an auth param is missing - don't continue any further
                $this->response(array('error' => "Access violation detected. Please retry your request."), 400);
                exit;
            }
        }

        // Get the user's ID from their session
        $params['user_id'] = $this->session->userdata('user_id');

        // User is signed in
        if ($params['user_id'] != null) {
            // Redirect the user to /oauth/authorise route
            redirect('/oauth2/authorize');
        }else {
             // User is not signed in, show the sign-in form
            echo form_open('/oauth2/signin');
            echo form_label('Username', 'username');
            echo form_input('username', 'f4hem');
            echo form_label('Password', 'password');
            echo form_password('password', 'f4hem');
            echo form_submit('signin', 'Sign In!');
            echo form_close();
        }
    }

    public function logout_GET(){
        $result = $this->session->unset_userdata('user_id');

        if($result){
            echo "Logged out";
        }
    }

    public function signin_POST(){

        // Retrieve the auth params from the user's session
        $params['client_id'] = $this->session->userdata('client_id');
        $params['client_details'] = $this->session->userdata('client_details');
        $params['redirect_uri'] = $this->session->userdata('redirect_uri');
        $params['response_type'] = $this->session->userdata('response_type');
        $params['scopes'] = $this->session->userdata('scopes');

        // Process the sign-in form submission
        if ($this->input->post('signin') != null) {
            try {

                // Get username
                $u = $this->input->post('username');
                if ($u == null || trim($u) == '') {
                    throw new Exception('please enter your username.');
                }

                // Get password
                $p = $this->input->post('password');
                if ($p == null || trim($p) == '') {
                    throw new Exception('please enter your password.');
                }

                // Verify the user's username and password
                // Set the user's ID to a session
                if($u == 'f4hem' && $p == 'f4hem') {
                    $this->session->set_userdata('user_id', 'f4hem');
                }

            } catch (Exception $e) {
                $params['error_message'] = $e->getMessage();
            }
        }

         // Get the user's ID from their session
        $params['user_id'] = $this->session->userdata('user_id');

        // User is signed in
        if ($params['user_id'] != null) {
            // Redirect the user to /oauth/authorise route
            redirect('/oauth2/authorize');
        }else {
             // User is not signed in, show the sign-in form
            echo form_open('/oauth2/signin');
            echo form_label('Username', 'username');
            echo form_input('username', 'f4hem');
            echo form_label('Password', 'password');
            echo form_password('password', 'f4hem');
            echo form_submit('signin', 'Sign In!');
            echo form_close();
        }
    }

    public function authorize_GET()
    {   
        // Retrieve the auth params from the user's session
        $params['client_id'] = $this->session->userdata('client_id');
        $params['client_details'] = $this->session->userdata('client_details');
        $params['redirect_uri'] = $this->session->userdata('redirect_uri');
        $params['response_type'] = $this->session->userdata('response_type');
        $params['scopes'] = $this->session->userdata('scopes');

        // Check that the auth params are all present
        foreach ($params as $key=>$value) {
            if ($value === null) {
                // Throw an error because an auth param is missing - don't continue any further
                $this->response(array('error' => "Access violation detected. Please retry your request."), 400);
                exit;
            }
        }

        // Get the user ID
        $params['user_id'] = $this->session->userdata('user_id');

        // User is not signed in so redirect them to the sign-in route (/oauth/signin)
        if ($params['user_id'] == null) {
            redirect('/oauth2/signin');
        }

        // Show the user a form so they can approve or deny requests
        // Specific details about the access token they're requesting should be shown here...
            //e.g. profile_information will allow basic details such as name, profile picture etc to be accessed.
        echo "Hey there ".$params['user_id'].", ".$params['client_details']['name']." would like to to access your data. Allow this?";
        //echo print_r($params);

        echo '<ul>';
        for ($i=0; $i < count($params['scopes']); $i++) { 
            echo '<li>'.$params['scopes'][$i]['description'].'</li>';
        }
        echo '</ul>';

        echo form_open('/oauth2/authorize');
        echo form_submit('approve', 'Allow');
        echo form_submit('approve', 'Deny');
        echo form_close();
    }

    public function authorize_POST(){
        
        // Retrieve the auth params from the user's session
        $params['client_id'] = $this->session->userdata('client_id');
        $params['client_details'] = $this->session->userdata('client_details');
        $params['redirect_uri'] = $this->session->userdata('redirect_uri');
        $params['response_type'] = $this->session->userdata('response_type');
        $params['scopes'] = $this->session->userdata('scopes');

        // Check that the auth params are all present
        foreach ($params as $key=>$value) {
            if ($value === null) {
                // Throw an error because an auth param is missing - don't continue any further
                $this->response(array('error' => "Access violation detected. Please retry your request."), 400);
                exit;
            }
        }

        // Get the user ID
        $params['user_id'] = $this->session->userdata('user_id');

        // User is not signed in so redirect them to the sign-in route (/oauth/signin)
        if ($params['user_id'] == null) {
            redirect('/oauth2/signin');
        }

        // Process the authorise request if the user's has clicked 'approve' or the client
        if ($this->input->post('approve') == 'Allow') {

            // Generate an authorization code
            $code = $this->authserver->getGrantType('authorization_code')->newAuthoriseRequest('user', $params['user_id'], $params);

            // Redirect the user back to the client with an authorization code
            $redirect_uri = League\OAuth2\Server\Util\RedirectUri::make(
                $params['redirect_uri'],
                array(
                    'code'  =>  $code,
                    'state' =>  isset($params['state']) ? $params['state'] : ''
                )
            );
            redirect($redirect_uri);
        }

        // If the user has denied the client so redirect them back without an authorization code
        if($this->input->post('approve') == 'Deny') {
            $redirect_uri = League\OAuth2\Server\Util\RedirectUri::make(
                $params['redirect_uri'],
                array(
                    'error' =>  'access_denied',
                    'error_message' =>  $this->authserver->getExceptionMessage('access_denied'),
                    'state' =>  isset($params['state']) ? $params['state'] : ''
                )
            );
            redirect($redirect_uri);
        }
    }

    public function access_token_POST()
    {
        try {

            // Tell the auth server to issue an access token
            $response = $this->authserver->issueAccessToken();
            $this->response($response, 200);

        } catch (League\OAuth2\Server\Exception\ClientException $e) {

            // Throw an exception because there was a problem with the client's request
            $response = array(
                'error' =>  $this->authserver->getExceptionType($e->getCode()),
                'error_description' => $e->getMessage()
            );

            $this->response($response, 400);

        } catch (Exception $e) {

            // Throw an error when a non-library specific exception has been thrown
            $response = array(
                'error' =>  'undefined_error',
                'error_description' => $e->getMessage()
            );

            $this->response($response, 400);
        }
    }

    public function verify_token_GET(){
        
        $server = new League\OAuth2\Server\Resource(
            new League\OAuth2\Server\Storage\PDO\Session($db)
        );

        try {
            $server->isValid();

            /*
            echo $server->getOwnerType();
            echo $server->getOwnerId();  
            echo $server->getClientId(); 
            echo $server->getAccessToken();
            */

            // Token is valid, return a response
            $response = array(
                'status'        => 'valid',
                'attributes'    => array(
                    'owner'  => array(
                        'type'  => $server->getOwnerType(),
                        'id'    => $server->getOwnerId()
                    ),
                    'client' => array(
                        'id'    => $server->getClientId()
                    ),
                    'scopes' => $server->getScopes()
                )
            );

            $this->response($response, 200);

        }
        catch (League\OAuth2\Server\Exception\InvalidAccessTokenException $e)
        {
            $response = array(
                'status' => 'invalid'
            );

            $this->response($response, 200);
        }
    }

    public function friends_GET(){
        
        $server = new League\OAuth2\Server\Resource(
            new League\OAuth2\Server\Storage\PDO\Session($db)
        );

        try {
            $server->isValid();

            if($server->hasScope('profile_information')){
                $response = array(
                    'friends'    => array(
                        'count'       => 2,
                        'collection'  => array(
                            'Joel Murphy', 
                            'Alex Murphy'
                        )
                    )
                );

                $this->response($response, 200);
            }else{
                echo "no";
            }

        }
        catch (League\OAuth2\Server\Exception\InvalidAccessTokenException $e)
        {
            $response = array(
                'status' => 'Invalid access token.'
            );

            $this->response($response, 200);
        }
    }
}