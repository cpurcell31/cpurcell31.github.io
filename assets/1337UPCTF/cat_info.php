<?php    
    $kittenID = $_GET['id'];
    $cmd = escapeshellcmd("/var/www/html/cat_info/main -c $kittenID");
    $output = shell_exec($cmd);

    if(sizeof(explode(" ", $kittenID)) === 1) {
        header('Content-type: application/json'); /* So it only returns as JSON when there is
                                                     no space character? */
        echo json_encode($output);
        die;
    }
    
    echo "<pre>".$output."</pre>";
?>