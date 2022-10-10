<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

print("
<html>
<title>CVE Feed</title>
<head>
    <style>
      table {
        border-spacing: 1px;
        table-layout: fixed;
        margin-left: auto;
        margin-right: auto;
        width: 600px;
      }
      th {
        border: 8px solid #0;
        text-align: left;
        word-break: break-all;
        font-style: normal;
        font-size: 18px;
        font-weight: bold;
      }
      td {
        border: 0px solid #666;
        text-align: left;
        word-break: break-word;
        color: grey;
        font-style: normal;
        font-size: 16px;
        font-weight: normal;
        font-family: \"Times New Roman\", Times, serif;
      }
      a:link {
        color: black;
	text-decoration: none;
      }
      a:visited {
        color: grey;
  	text-decoration: none;
      }
      a:hover {
        color: none;
        text-decoration: underline;
     }
    </style>
</head>
<body>");

?>
