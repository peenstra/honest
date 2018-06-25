<?php

// // Cross-Site Request Forgery (CSRF) preventy
// // https://github.com/mebjas/CSRF-Protector-PHP/wiki
// include_once 'csrfp/libs/csrf/csrfprotector.php';
//
// //Initialise CSRFGuard library
// csrfProtector::init();

$error = '&nbsp;';
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true
]);

$_SESSION = array(); // maak het sessie array leeg
session_unset();
session_destroy();

// Databaseverbinding maken
require_once('inc/config.inc.php');
// Mobile_Detect script
require_once 'mobile//Mobile_Detect.php';

/* http://www.openwall.com/articles/PHP-Users-Passwords */
if ($_SERVER['REQUEST_METHOD'] == 'POST')
{
	if( isset( $_POST['user'], $_POST['pass']) )
	{

		//Hij zou eigenlijk op TRUE moeten staan, maar krijg hem daar niet mee werkend
		$use_pwqcheck = FALSE;
		// We can override the default password policy
		$pwqcheck_args = '';
		#$pwqcheck_args = 'config=/etc/passwdqc.conf';

		// Base-2 logarithm of the iteration count used for password stretching
		$hash_cost_log2 = 8;
		// Do we require the hashes to be portable to older systems (less secure)?
		$hash_portable = FALSE;

		/* Dummy salt to waste CPU time on when a non-existent 3name is requested.
		 * This should use the same hash type and cost parameter as we're using for
		 * real/new hashes.  The intent is to mitigate timing attacks (probing for
		 * valid usernames).  This is optional - the line may be commented out if you
		 * don't care about timing attacks enough to spend CPU time on mitigating them
		 * or if you can't easily determine what salt string would be appropriate. */
		$dummy_salt = '$2a$08$1234567890123456789012';

		// Are we debugging this code?  If enabled, OK to leak server setup details.
		$debug = FALSE;

		function fail($pub, $pvt = '')
		{
			global $debug;
			$msg = $pub;
			if ($debug && $pvt !== '')
				$msg .= ": $pvt";
		/* The $pvt debugging messages may contain characters that would need to be
		 * quoted if we were producing HTML output, like we would be in a real app,
		 * but we're using text/plain here.  Also, $debug is meant to be disabled on
		 * a "production install" to avoid leaking server setup details. */
			exit("Er is een fout opgetreden ($msg).\n");
		}

		function my_pwqcheck($newpass, $oldpass = '', $user = '')
		{
			global $use_pwqcheck, $pwqcheck_args;
			if ($use_pwqcheck)
				return pwqcheck($newpass, $oldpass, $user, '', $pwqcheck_args);

		/* Some really trivial and obviously-insufficient password strength checks -
		 * we ought to use the pwqcheck(1) program instead. */
			$check = '';
			if (strlen($newpass) < 7)
				$check = 'way too short';
			else if (stristr($oldpass, $newpass) ||
				(strlen($oldpass) >= 4 && stristr($newpass, $oldpass)))
				$check = 'is based on the old one';
			else if (stristr($user, $newpass) ||
				(strlen($user) >= 4 && stristr($newpass, $user)))
				$check = 'is based on the username';
			if ($check)
				return "Bad password ($check)";
			return 'OK';
		}

		function get_post_var($var)
		{
			$val = trim($_POST[$var]);
			if (get_magic_quotes_gpc())
				$val = stripslashes($val);
			return $val;
		}

		//header('Content-Type: text/plain');

		$op = $_POST['op'];
		if ($op !== 'new' && $op !== 'login' && $op !== 'change')
			fail('Onbekende aanvraag');

		$user = strtolower(get_post_var('user'));
		/* Sanity-check the username, don't rely on our use of prepared statements
		 * alone to prevent attacks on the SQL server via malicious usernames. */
		if (!preg_match('#^[a-z0-9][a-z0-9_.-]{0,63}@([a-z0-9]+\.)*[a-z0-9][a-z0-9\-]+\.([a-z]{2,6})$#i', $user))
			fail('Foute gebruikersnaam');

		$pass = get_post_var('pass');
		/* Don't let them spend more of our CPU time than we were willing to.
		 * Besides, bcrypt happens to use the first 72 characters only anyway. */
		if (strlen($pass) > 72)
			fail('Het opgegeven wachtwoord is te lang');


		$db = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);
		if (mysqli_connect_errno())
			fail('MySQL connect', mysqli_connect_error());

		$hasher = new PasswordHash($hash_cost_log2, $hash_portable);

		$hash = '*'; // In case the user is not found
		($stmt = $db->prepare('SELECT klant_wachtwoord FROM ch_klanten WHERE klant_email=?'))
			|| fail('MySQL prepare', $db->error);
		$stmt->bind_param('s', $user)
			|| fail('MySQL bind_param', $db->error);
		$stmt->execute()
			|| fail('MySQL execute', $db->error);
		$stmt->bind_result($hash)
			|| fail('MySQL bind_result', $db->error);
		if (!$stmt->fetch() && $db->errno)
			fail('MySQL fetch', $db->error);

		// Mitigate timing attacks (probing for valid usernames)
		if (isset($dummy_salt) && strlen($hash) < 20)
			$hash = $dummy_salt;

		if ($hasher->CheckPassword($pass, $hash))
		{

			$sUserQ = "SELECT klant_id, klant_email, klant_wachtwoord, klant_level, klant_vnaam, klant_anaam, klant_geslacht FROM ch_klanten WHERE klant_wachtwoord = ? LIMIT 0,1";
			if ($stmt = mysqli_prepare($database_connection, $sUserQ)or die(mysqli_error($database_connection)))
			{

				mysqli_stmt_bind_param($stmt, "s", $hash);

				mysqli_stmt_execute($stmt);

				mysqli_stmt_bind_result($stmt, $klant_id, $klant_email,$klant_wachtwoord, $klant_level, $klant_vnaam, $klant_anaam, $klant_geslacht);

				/* fetch values */
				if(mysqli_stmt_fetch($stmt)){

					session_regenerate_id(); //genereert elke keer een nieuwe sessie om zo sessie hacking te voorkomen

					$_SESSION['login'] = 1;
					// $_SESSION['user'] = $klant_vnaam.' '. $klant_anaam;
					$_SESSION['klant_id'] = $klant_id;
          // Geslacht wordt speciaal gebruikt voor Honest Throwdown 2018
					$_SESSION['klant_geslacht'] = $klant_geslacht;

					//Langere tijd voor mij gebruiken dan voor de normale gebruiker
					if($_SESSION['klant_id'] == 1){
						$_SESSION['sessie_timeout'] = time() + '28800';
					}
					else {
						//sessie tijd loopt af na 2uur
						$_SESSION['sessie_timeout'] = time() + '7200';
					}
					$_SESSION['level'] = $klant_level;
					//$_SESSION['huidig_ip']= $_SERVER['REMOTE_ADDR'];

					// Geen idee waarom dit niet werkt.........
					// if($_SESSION['klant_id']!= '3' || $_SESSION['klant_id']!= '1')
					// Dan maar op een 'slechte' manier gedaan

					// Tijdelijk uitgezet ivm vreemde ophogen tegoed
					if($_SESSION['klant_id']!= '1')
					{
						if($_SESSION['klant_id']!= '3')
						{

							$detect = new Mobile_Detect;

							$deviceType = ($detect->isMobile() ? ($detect->isTablet() ? 'tablet' : 'telefoon') : 'computer');
							// Neemt te veel ruimte Database in
							// $user_agent = htmlentities($_SERVER['HTTP_USER_AGENT']);
							$ipadres = $_SERVER['REMOTE_ADDR'];

							foreach($detect->getProperties() as $name => $match):
									$check = $detect->version($name);
									if($check!==false):
							$browser=$name;
							?>

							<?php //echo($check);
							endif;
							endforeach;

							//User Agents toevoegen aan database, kijken wat voor device het meest gebruikt wordt en daarop het design/ontwikkeling aanpassen
							$iUserAgentQ = "INSERT INTO ch_klanten_login_devices (klant_id,device,browser,ipadres)
																												VALUES (?,?,?,?)";
							if($stmt = mysqli_prepare($database_connection2, $iUserAgentQ)or die(mysqli_error($database_connection2)))
							{

								mysqli_stmt_bind_param($stmt, "ssss", $klant_id,$deviceType,$browser,$ipadres);

								mysqli_stmt_execute($stmt);

								mysqli_stmt_close($stmt);


							}


						}
					}

				header('location: index.php');
			}


			}
		}
		else
		{
			$sUserQ = "SELECT klant_id, klant_email FROM ch_klanten WHERE klant_email = ? LIMIT 0,1";
			if ($stmt = mysqli_prepare($database_connection, $sUserQ)or die(mysqli_error($database_connection)))
				{

					mysqli_stmt_bind_param($stmt, "s", $user);

					mysqli_stmt_execute($stmt);

					mysqli_stmt_bind_result($stmt, $klant_id, $klant_email);

					/* fetch values */
					mysqli_stmt_fetch($stmt);

					if(isset($klant_id)){
						$ipadres = $_SERVER['REMOTE_ADDR'];

						//Fail login toevoegen aan database
						$iFailLoginQ = "INSERT INTO ch_klanten_login_fail (klant_id,ipadres)
																											VALUES (?,?)";
						if($stmt = mysqli_prepare($database_connection2, $iFailLoginQ)or die(mysqli_error($database_connection2)))
						{

							mysqli_stmt_bind_param($stmt, "ss", $klant_id, $ipadres);

							mysqli_stmt_execute($stmt);

							mysqli_stmt_close($stmt);

						}
					}
					else {

						$error='Ongeldige gebruikersnaam en/of wachtwoord';
						$op = 'fail'; // Definitely not 'change'

					}
				}
				//$what = 'Authentication failed';

				$error='Ongeldige gebruikersnaam en/of wachtwoord';
				$op = 'fail'; // Definitely not 'change'

		}

		unset($hasher);

		$db->close();
		mysqli_close($database_connection);
		mysqli_close($database_connection2);


	}
}
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
	<head>
    <meta http-equiv="Content-type" content="text/html;charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1">
		<title>CrossFit Honest Login</title>
    <link rel="stylesheet" type="text/css" href="https://www.crossfithonest.nl/leden/css/style.css" />
		<link rel="stylesheet" type="text/css" href="https://www.crossfithonest.nl/leden/font/CrossFitHonestTRADE.css" />
	</head>
		<body>
			<center>
			<div id="container">
				<div id="login">
					<div align="center"><b style="color: red;"><?php echo $error; ?></b></div>
					<h2 >CrossFit Honest Login</h2>
					<b style="color: #c90101;">Let op!</b> Wachtwoord is hoofdletter gevoelig
						<table width="330px" border="0">
							<form action="<?= basename(__file__);?>" method="post" accept-charset="UTF-8" >
								<input type="hidden" name="op" value="login">
								<table>
									<tr>
										<td>Gebruiker:</td>
										<td><input type="text" placeholder="je@email.nl" class="login" name="user" id="user" autofocus /></td>
									</tr>
									<tr>
										<td>Wachtwoord:</td>
										<td><input type="password" placeholder="wachtwoord" class="login" name="pass" id="pass" autocomplete="off" /></td>
									</tr>
									<tr>
										<td>&nbsp;</td>
										<td><b style="color: red; font-size:12px;"><a href="wachtwoord_vergeten.php">Wachtwoord vergeten</a></b></td>
									</tr>
									<tr>
										<td>&nbsp;</td>
										<td><input class="login" type="submit" value="Login" /></td>
									</tr>
								</table>
							</form>
						</table>
				</div>
			</div>
		</center>
	</body>
</html>
