# README

## Description

MySSL is a .NET library for creating self-signed certificates.  It is useful in situations where you would like to serve a local web application over SSL.

## Installation

Using Nuget

<pre>
Install-Package MySSL
</pre>

## Usage

### Creating a self-signed SSL certificate

1. Create a certificate authority

<pre>
var authority = new CertificateAuthority("MyAuthority").ToX509Certificate();
</pre>

2. Create an SSL certificate from the authority for localhost

<pre>
var sslCert = authority.CreateSSL(); 
</pre>

3. Install the certificates

<pre>
var certInstaller = new CertificateInstaller();
certInstaller.InstallAuthority(authority);
certInstaller.InstallSSLCertificate(sslCert);
</pre>
