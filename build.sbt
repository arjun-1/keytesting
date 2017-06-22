name := "untitled"

version := "1.0"

scalaVersion := "2.12.2"


libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.53",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.53",
  "com.github.karasiq" %% "cryptoutils" % "1.4.2"
)