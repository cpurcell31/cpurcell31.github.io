<?php
    $projectRoot = realpath(__DIR__);
    
    $relativePath = $_GET['path'];
    $absolutePath = realpath($projectRoot . "/" . $relativePath);

    if ($absolutePath === false || strcmp($absolutePath, $projectRoot . DIRECTORY_SEPARATOR) < 0 || strpos($absolutePath, $projectRoot . DIRECTORY_SEPARATOR) !== 0) {
        echo "Not yet!";
        http_response_code(404);
        die;
    }

    $splittedPath = explode('.', $relativePath);
    $fileExtension = end($splittedPath);

    if ($fileExtension === "jpg") {
        header('Content-type: image/jpeg');
        $pictureName = "photo";
        
    } else {
        header('Content-type: image/'.$fileExtension);
        $pictureName = file_get_contents("/flag1.txt");
    }

    header("Content-Disposition: filename=$pictureName-file.$fileExtension");
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    readfile($relativePath);
    die;
?>