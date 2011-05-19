Phreebird Suite 1.0
8-Nov-2010
Dan Kaminsky
dan@doxpara.com

Contents
========
1.  Phreebird: Zero Configuration DNSSEC Proxy
2.  Phreeload: DNSSEC Augmentation Shim for OpenSSL-based Applications
               (Implements sample schema for key delivery over DNSSEC)
3.  Sample Clients:
     a. ldns_chase:  End-To-End DNSSEC Queries w/ LDNS Chasing
     b. unbound_trace:  End-to-End DNSSEC Queries w/ LibUnbound tracing
4.  Phreeshell:  Federated Identity Patch for OpenSSH
5.  Patch for LDNS Support of HTTP Virtual Channel

Introduction
============

The DNS root is signed.

Now what?

This is not a small question.  After a decade long struggle, it is now
possible to acquire cryptographic assurance of the integrity of
data delivered via the DNS.  What do we do with this new capability?

I propose we use this to resolve another epic struggle of Information
Technology:  The battle to fix authentication across organizational
boundaries.

I'm not going use this README file to go through the full philosophy
behind the Phreebird suite.  But put simply, X.509 based PKI fails due
to a series of problems DNSSEC simply does not have.  If we can find
a way to use DNSSEC to address the problem of bootstrapping trust
across organizational boundaries, we can start fulfilling promises
made before the turn of the century.

Given the right code, we can build the Domain Key Infrastructure.  The
time is right for DKI.

Phreebird:  Making DNSSEC Deployment On The Server Easy
=======================================================

Phreebird is a DNSSEC proxy that operates in front of an existing
DNS server (BIND, Unbound, PowerDNS, Microsoft DNS, QIP) and
supplements its records with DNSSEC responses.  Features of Phreebird
include:

1.  Automatic key generation
2.  Realtime record signing -- no "batch signing"
3.  Support for arbitrary responses -- if your server emits ten different 
responses, Phreebird will create ten different signatures
4.  Zero configuration, even for multiple zones (all zones share the same key)
5.  Support for realtime generation of NSEC3 records, a.k.a. "NSEC3 White Lies"
6.  Caching of signed answers (with a maximum bound on how large the cache can 
get)
7.  Rate limiting for NSEC3 responses
8.  Experimental Support for "time.arpa" Coarse Time over DNS
9.  Experimental Support for "HTTP Virtual Channel" DNS over HTTP

Setting up Phreebird is fairly straightforward:

1.  Set up a test domain, or set of domains.  
   (At this time, Phreebird is not recommended for production domains.  Wait
   till 1.1, after the security community has had a good chance to bash it.)
   a.  It is easiest if you create a .org domain at GoDaddy
2.  Configure the name server for the domain to run on port 50053
3.  Launch Phreebird on this server.  The first time you do so, use the -g flag
    to generate a key.
4.  Run "dig @127.0.0.1 domain.com DS" to determine the hash of the key now 
    associated with your domain.
5.  Go to GoDaddy's web interface, open up your particular domain, click 
"DNSSEC Tools", and insert the DS information from the dig command
6.  That's it.  In about 30 seconds, valid signed records will be available via
the Internet.

Phreeload:  Making DNSSEC Deployment On The Client Easy
=======================================================

One of the more common questions about DNSSEC I hear from architects is:

"What should this mean for client UI?  Should we be informing the user that
IP addresses were successfully resolved?"

The answer is no!  There are many ways traffic can be hijacked; cache
poisoning is just one.  Raising this particular error is simply inside
baseball.

Now, that being said, we have an entire UI infrastructure around SSL/TLS,
specifically around whether certificate validation succeeded or failed.
X.509 may not yield good answers to that question at a reasonable price,
but DNSSEC can -- and using Phreeload, we can migrate the dependent 
infrastructure from X.509 to DNSSEC without changing a single line of code.  
What's actually happening is, instead of looking inside the certificate and 
evaluating the X.509 inside, properties of the certificate (perhaps its hash, 
perhaps the hash of the public key) are compared against validated records 
retrieved via DNS.

Implementation wise, the way Phreeload works is by hijacking a function inside of OpenSSL,
x509_verify_cert.  Unix operating systems make it very easy to do this, via
the LD_PRELOAD mechanism.  As such, causing (for example) curl to use DNSSEC
lookups is as easy as:

phreeload curl https://www.hospital-link.org

Alternatively, if all binaries run in a given shell should use phreeload:

EXPORT LD_PRELOAD=/usr/local/lib/phreeload.so
curl https://www.hospital-link.org

(There are ways of making *every binary on a system preload Phreeload, but that 
doesn't seem like a good idea yet.)

Phreeload supports some debug statements.  Running:

export DNSSEC_DEBUG=1

...will cause any application using Phreeload to emit debug statements during 
execution.

Of course, just because records are being received from DNS, does not describe 
how those records are being encoded.  There are an infinite number of possible 
ways of encoding trusted information into the DNS namespace; it's going to be a 
major challenge to determine which mechanism should be used.  Phreeload 
incorporates one proposed methodology, but I make no claims towards its 
perfection.  I hope its existence -- and the framework around it -- make it 
easier for people to develop proper schemas, however.

KEY1:  A Semi-Proposed Schema For TLS (And Other) Keys Over DNS
===============================================================

KEY1 uses TXT records to encode asserted key material.  A sample KEY1 record 
might look like:

www.foo.com IN TXT "v=key1 ha=sha1 h=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"

The full list of supported entities are:

v=key1:     Version
            What protocol is being spoken for the rest of this record.  Must
            be "key1", though may support upward compatibility.
ha=sha1:    Hash Algorithm
            What hash algorithm is being used across the hashed data.
            Only SHA-1 supported for now.  Default is sha1.
sts=[0|1]:  Strict-Transport-Security:
            Whether insecure (http) access to www.foo.com should be allowed
sn=[0|1]:   Secure Negotiation:
            Whether secure renegotiation will be present at this HTTPS endpoint
lh=[0|1]:   LiveHash
            Whether, upon a failed resolution for www.foo.com, a second lookup 
            to _tlshash-f1d2d2f924e986ac86fdf7b36c94bcdf32beec15.www.foo.com
            should be attempted.  (Not done by default due to performance
            implications.)
hr=[cert|pubkey]:  Hash Range
            If set to "cert" (or unset), the hash validated is the hash of
            the entire certificate.  If set to "pubkey", the hash validated is 
            the hash of the public key in the certificate.  It is likely that a 

It is likely that another mode will be added for Phreeload 1.1:

pk=<pubkey>: This will be the raw, Base64 encoded version of the RSA public 
             key.  A comma will be used to separate modulus from exponent.
             
I could be convinced to support another format, but here's the thinking behind 
some of these design decisions:

1) Why TXT?  Why not CERT or a new RR type?

TXT is getting a little crowded -- the last four major efforts to put complex 
data in DNS have *all* eschewed custom types, and have put their data into TXT.  
These four are:
have all settled on TXT.  These efforts are:

DKIM
HPA (the PGP key distribution mechanism in GPG)
IPsec (there's even an RFC)
SPF

(Three of these four use the v=abc# syntax to disambiguate across one another, 
as do we.)

In general, advantages of TXT are:

a) TXT records can be entered without requiring a record compiler
b) TXT records can be entered without upgrading the name server
c) Over time, we can expect more and more ancillary data (such as STS) to be 
shipped alongside keys.  IT has effectively abandoned binary protocols for 
flexible data types, in favor of XML and JSON.  I have a distinct fear that any 
attempt to put flexible data types into DNS, in a binary form, is going to end 
up coalescing on ASN.1.  We stopped using that protocol for a reason.

Disadvantages of TXT are:

a) Individual subcomponents of TXT records are limited to 256 bytes.  We can 
get around that by specifying that subcomponents, which are delivered in order, 
must be concatenated together.
b) Hex and base64 is somewhat less dense, bit for bit, than the 8 bit binary
modes that DNS can in fact deliver
c) We're abandoning a degree of freedom DNS gives us.

Right now, I'm leaning pretty far towards a TXT encoding.  But I'm not exactly 
heartbroken to be delivering a platform for people to implement their own 
chosen schemas...lets figure this out.

2) Why are you placing your records in www.foo.com, rather than 
_tlshash.www.foo.com?

Wildcards and CNAMEs.  Suppose I have a CNAME from www.bar.com to www.foo.com.  
www.bar.com will automatically get the TXT record of www.foo.com, but it will 
not automatically get the TXT record from _tlshash.www.foo.com.

Similarly, *.foo.com can absorb all TXT records.  However, _tlshash.*.foo.com 
isn't actually legal in most nameservers.  This could be fixed, but it'd be 
ugly.


Sample Clients:  LDNS Chasing and Unbound Tracing
=================================================

There's a lot up there for system administrators, but what about developers?  
What are they supposed to noodle on, regarding this whole DNSSEC thing?

It turns out that DNSSEC wasn't *quite* designed to support key management.  It 
was definitely intended to allow arbitrary data to be chained to delegations 
within the DNS root, but the expected consumers of this data was expected to be 
other name servers.  The idea that end clients would need to validate data 
themselves was somewhat supported, but not as a first class citizen.

No matter.  There's enough there to get end clients to be able to validate 
DNSSEC data, via libraries that are already available.  Included in the 
Phreebird suite are ldns_chase.c and unbound_trace.c.  I've wrapped the actual 
query functionality up in a helper function, and put how that function would be 
used into main.  (If I'm going to create a library that wraps these libraries, 
it'll rationalize actually extracting values a little better than either 
library does right now.)

To answer some questions:

1) What is LDNS doing when it chases, and what is Unbound doing when it traces?

DNSSEC has a feature called CD, for Checking Disabled.  This allows a end node 
to get the RRSIG (the signature) for a record.  Now, this is just the end 
signature -- foo.com's signature of www.foo.com -- but that's enough to go 
recursive, i.e. asking for foo.com's signature from com, and then com's 
signature from root.  Then the root signature can be compared against the 
embedded root key, and the entire chain can be validated.  Works reasonably 
well.

Another approach to end-to-end DNSSEC is simply to embed a validating resolver 
into your application.  It's not 1983; phones now outstrip supercomputers then.  
LibUnbound just goes to the root like a normal server would and iterates its 
way down from root, through com, through foo.com, checking signatures along the 
way.

Either way, you're looking at only a few lines of code to do end-to-end lookups 
in your app.

2) Are there any circumstances where chasing or tracing won't work?

Hotel networks are evil.

There do exist a decent number of networks where arbitrary DNS traffic gets 
stomped on -- the Internet really is stuck in 2001.  So, what can you do?

What we always do:  Tunnel.  There are two approaches.  One of which, tunneling 
over HTTP (which makes things faster!), has supporting code in the patches 
directory (see:  ldns-hvc.patch).  The other concept is to include the DNSSEC 
chain, as a whole, in an X.509 certificate.  This has actually been implemented 
by Google's Adam Langley in a custom build of Chrome, but is complicated enough 
that it's being saved for Phreebird 1.1.

A third approach, interestingly, is to use the batched chain being delivered 
over X.509, and put it in a known portion of the HTTP or (non-validated) HTTPS 
namespace.  This could work as well.  Feedback is requested.

Phreeshell:  Federated Identity with OpenSSH
============================================

One of the primary reasons authentication systems stop scaling is because they 
treat identities outside their native organization as the exception, not the 
rule.

Think about it:  Workgroups begat domains, and domains begat forests, but still 
this wasn't enough -- cross forest trusts were required, and they're all 
manually built.

Why are they built?  Because we have:

* Clients
* Customers
* Vendors
* Partners
* Contractors
* Outsourcers
* Governments (and not necessarily your own)

Identities in all of these organizations need to be authenticated.  Cross 
organizational authentication is no more the exception than 
cross-organizational email -- you need to be able to mail anyone.

Enter Phreeshell.  Phreeshell is a *very* small demonstration of how DNSSEC 
takes a hard thing, and makes it painfully easy.  It allows SSH Public Keys to 
be retrieved over DNS, so instead of placing:

ssh-dss AAAAB3NzaC1kc3MAAACBANeQ96PsGgv+rldXicckc/beYv/
NkuCAhVLK3djhjdOlYPW8YIKHT6vI2z9nvYZRTa/
0Ga2PpeOwFYcVdQNODCFBhRU0EdhNnBCFpYp8gY4hXamkaMcjpTOXbycheuNR16CYVS4QN2mt8t5A+
kBeOeDt5kr97iujOYgz0zVIyZ4pAAAAFQCdaRAmHzhXkZUJmNndGcaz5l5mmwAAAH8r5Kc/
jsayRRhic+JtvCmkqfQUDBqk5PIbL9wNtRW67+
HPVSA6uElebPblHU72hgdhs6it0MkPyXVFNpTPE63SpNibZ6BsB9ZOcy+
qInHbHgOFR512IYA0Qgh170g2BMqWU/nzusxcvLSv0+5q6RP6o/
tvPe3pmK4bUwKMc9vVAAAAgGxDLEdn35lCM4kdI9UCFfxjXVAD7/
PyzsM8j9nRHbvfeiNyubxsQtiziLD3XWAk7SHemY5jwVWInpzlxZiqwH6ccKHegXev4vVWrRfEIxQkl
SDGRPGp1TctpjTyoHsqGpoPoy8MDitcxFhQ5n0PSV/Z+gNOBSUCQIT99uqAWQM5 
dan@remote-support.org

...into authorized_keys2, one just places into authorized_keys2:

dan@remote-support.org

And now, this works:

ssh dan@remote-support.org^root@somecustomer.org
Last login:  Wed Jul 28 09:56:17 2010 from 70.165.147.239
somecustomer:~# cat .ssh/authorized_keys2
dan@remote_support.org

Phreeshell was actually written before Phreeload, so it doesn't have the 
benefit of any of the advanced schema work.  Right now, a custom RR type is 
retrieved from dan._sshpubkey.remote-support.org, the contents of which equal 
the above public key.

A future build of Phreeshell will certainly change this schema.  SSH, like SSL 
and many other protocols, actually shared pubkeys explicitly over the wire.  So 
I'll probably be porting KEY1 to PhreeShell.

