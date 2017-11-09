<?php
$id = $_GET['id'];
$name = $_GET['name'];
echo $id . "<br />";
echo $name . "<br />";
$con = mysqli_connect("127.0.0.1","root","passwd","dataa","5000");
if (!$con)
{
  die('Could not connect: ' . mysql_error());
}

$result = mysqli_query($con,"SELECT * FROM tablee WHERE id = $id AND name = '$name'");

while($row = mysqli_fetch_assoc($result))
{
  echo $row['id'] . " " . $row['name'] . " " . $row['sex'];
  echo "<br />";
}
mysqli_close($con);
?>
