# ==========================================================================
#
# ZoneMinder Tapo C200 IP Control Protocol Module
# $Date: 2021-05-09$, $Revision: 0001$
#
# Copyright 2021 https://github.com/oparm
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# ==========================================================================
#
package ZoneMinder::Control::TapoC200;

use 5.006;
use strict;
use warnings;

use IO::Socket::SSL;
use Time::HiRes qw(usleep);
use Data::Dumper;
use LWP::UserAgent;
use JSON::Parse 'parse_json';
use Bytes::Random::Secure qw(random_bytes_hex);
use Digest::SHA qw(sha256_hex sha256);
use Digest::MD5 qw(md5_hex);
use Crypt::CBC;
use MIME::Base64;
use JSON;

require ZoneMinder::Base;
require ZoneMinder::Control;

our @ISA = qw(ZoneMinder::Control);
 
our $VERSION = $ZoneMinder::Base::VERSION;
 
# ==========================================================================
#
# TAPO C200 IP Control Protocol
#
# ==========================================================================

my $tapo_c200_debug = 0;
my $step = 10;

use ZoneMinder::Logger qw(:all);
use ZoneMinder::Config qw(:all);
use ZoneMinder::Database qw(zmDbConnect);

my ($user, $pass, $host, $port, $retry_command);

sub open
{
    my $self = shift;
    $self->loadMonitor();

    if ($self->{Monitor}{ControlAddress} =~ /^([^:]+):([^@]+)@(.+)/) {
        $user = $1;
        $pass = $2;
        $host = $3;
    } else {
        Error("Control Address URL must be entered as 'admin:admin_password\@host:port', exiting");
        Exit(0);
    }
    $self->{retry}=1;

    if ($host =~ /([^:]+):(.+)/) {
        $host = $1;
        $port = $2;
    } else {
        $port = 443;
    }

    $self->{user} = $user;
    $self->{pass} = $pass;
    $self->{host} = "$host:$port";
    $self->{BaseURL} = "https://$host:$port";
    $self->{hashed_password} = uc(sha256_hex($self->{pass}));

    # Disable verification of Tapo C200 self-signed certificate
    use LWP::UserAgent;
    $self->{ua} = LWP::UserAgent->new(
        ssl_opts => {
            verify_hostname => 0,
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
        }
    );

    $self->{ua}->agent("ZoneMinder Control Agent/".ZoneMinder::Base::ZM_VERSION);

    if ($self->{user} ne 'admin') {
        Error("Username should be 'admin' but '$self->{user}' was found");
    }
    
    # Retrieve and store token during opening
    $self->setToken();

    $self->{state} = 'open';
    
    Info("Tapo C200 Controller opened");
}
sub close
{ 
    my $self = shift;

    $self->{user} = undef;
    $self->{pass} = undef;
    $self->{BaseURL} = undef;
    $self->{token} = undef;
    $self->{state} = 'closed';
}

sub printMsg
{
    my $msg = shift;

    if ($tapo_c200_debug == 1) {
        Info($msg);
    } else {
        Debug($msg);
    }
}
sub calcTag
{
    my $self = shift;
    my $payload = shift;

    my $tag = uc(sha256_hex(uc(sha256_hex($self->{pass})).$self->{cnonce}));
    $tag = uc(sha256_hex($tag.$payload.$self->{sequence}));
}
sub encryptRequest
{
    my $self = shift;
    my $msg = shift;

    Debug("clean message: $msg");
    my $cipher = Crypt::CBC->new(
        -key         => $self->{lsk},
        -iv          => $self->{ivb},
        -cipher      => 'Cipher::AES',
        -literal_key => 1,
        -header      => "none",
        -padding     => "standard",
        -keysize     => 16 );
    my $ciphertext = $cipher->encrypt($msg);
    Debug("encrypted: ".encode_base64($ciphertext,""));
    return($ciphertext);
}
sub decryptResponse
{
    my $self = shift;
    my $encmsg = shift;
    Debug("encmsg: ".encode_base64($encmsg,""));

    my $cipher = Crypt::CBC->new(
        -key         => $self->{lsk},
        -iv          => $self->{ivb},
        -cipher      => 'Cipher::AES',
        -literal_key => 1,
        -header      => "none",
        -padding     => "standard",
        -keysize     => 16 );
    my $msg = $cipher->decrypt($encmsg);
    Debug("clean message: $msg");
    return($msg);
}

sub generateEncryptionToken
{
    my $self = shift;
    my $type = shift;
    my $snonce = shift;
    my $hashedKey = uc(sha256_hex($self->{cnonce}.uc(sha256_hex($self->{pass})).$snonce));
    Debug("hashedKey ".$hashedKey);
    return(substr(sha256($type.$self->{cnonce}.$snonce.$hashedKey),0,16));
}

sub setToken
{
    my $self = shift;

    my $result = undef;
    my $token = undef;
    my $snonce = undef;

    $self->{cnonce} = uc(random_bytes_hex(8));
    my $payload = '{"method":"login","params":{"cnonce":"'.$self->{cnonce}.'","encrypt_type": "3","username":"'.$self->{user}.'"}}';
    Debug("first phase payload ".$payload);
    my $req1 = HTTP::Request->new(POST => $self->{BaseURL});
    $req1->header('User-Agent' => 'Tapo CameraClient Android');
    $req1->header('Accept-Encoding' => 'gzip, deflate');
    $req1->header('Accept' => 'application/json');
    $req1->header('Connection' => 'close');
    $req1->header('Host' => $self->{host});
    $req1->header('Referer' => $self->{BaseURL});
    $req1->header('requestByApp' => 'true');
    $req1->header('Content-Type' => 'application/json; charset=UTF-8');
    $req1->header('Content-Length' => length($payload));
    $req1->content($payload);
    my $response1 = $self->{ua}->request($req1);

    my $response2 = undef;
    if ($response1->is_success) {
       Debug("response first phase OK");
       $snonce = decode_json($response1->content)->{result}->{data}->{nonce};
       Debug("server nonce ".$snonce);
       if ($snonce eq "") {
          Exit(0);
       }
       my $digest_pass = uc(sha256_hex($self->{hashed_password}.$self->{cnonce}.$snonce));
       my $payload = '{"method": "login","params":{"cnonce": "'.$self->{cnonce}.'","encrypt_type": "3","digest_passwd": "'.$digest_pass.$self->{cnonce}.$snonce.'","username": "admin"}}';
       Debug("second phase payload".$payload);

       my $req2 = HTTP::Request->new(POST => $self->{BaseURL});
       $req2->header('User-Agent' => 'Tapo CameraClient Android');
       $req2->header('Accept-Encoding' => 'gzip, deflate');
       $req2->header('Accept' => 'application/json');
       $req2->header('Connection' => 'close');
       $req2->header('Host' => $self->{host});
       $req2->header('Referer' => $self->{BaseURL});
       $req2->header('requestByApp' => 'true');
       $req2->header('Content-Type' => 'application/json; charset=UTF-8');
       $req2->header('Content-Length' => length($payload));
       $req2->content($payload);
       $response2 = $self->{ua}->request($req2);
    } else {
       Error("FAIL init phase response1".$response1.as_string());
       Exit(0);
    }
    if ($response2->is_success) {
        my $cmd_error_code = decode_json($response2->content)->{result}->{error_code};
        if ($cmd_error_code == 0) {
            $self->{token} = decode_json($response2->content)->{result}->{stok};
            $self->{sequence} = decode_json($response2->content)->{result}->{start_seq};
            Debug("token -->".$self->{token});
            Debug("sequence -->".$self->{sequence});
            $self->{lsk} = $self->generateEncryptionToken("lsk", $snonce);
            $self->{ivb}=$self->generateEncryptionToken("ivb", $snonce);

            Debug("Token retrieved for ".$self->{BaseURL});
            return $self->{token};
        } elsif ($cmd_error_code == -40401) {
            Error("Invalid credentials for $self->{BaseURL}, exiting");
            Exit(0);
        }
    } else {
        Error("Could send request to retrieve token for $self->{BaseURL} : $response2->status_line()");
        
        return undef;
    }
}

sub sendCmd
{
    my $self = shift;
    my $cmd = shift;

    my $result = undef;
    my $token = undef;
    my $sequence = 0;

    my $encmsg = encode_base64($self->encryptRequest($cmd),"");
    my $payload='{"method": "securePassthrough", "params": {"request": "'.$encmsg.'"}}';
    printMsg("Send command seq:[$self->{sequence}] for $self->{BaseURL}/stok=$self->{token}/ds, $cmd");

    my $req = HTTP::Request->new(POST => "$self->{BaseURL}/stok=$self->{token}/ds");
    $req->header('User-Agent' => 'Tapo CameraClient Android');
    $req->header('Accept-Encoding' => 'gzip, deflate');
    $req->header('Accept' => 'application/json');
    $req->header('Connection' => 'close');
    $req->header('Host' => $self->{host});
    $req->header('Referer' => $self->{BaseURL});
    $req->header('requestByApp' => 'true');
    $req->header('Content-Type' => 'application/json; charset=UTF-8');
    $req->header('Seq' => $self->{sequence});
    $req->header(':Tapo_tag' => $self->calcTag($payload));
    $req->header('Content-Length' => length($payload));
    $req->content($payload);

    my $response = $self->{ua}->request($req);
    $self->{sequence}++;

    if ($response->is_success) {
        my $cmd_error_code = decode_json($response->content)->{error_code};

        if ($cmd_error_code == 0) {
            printMsg("Command sent successfully to $self->{BaseURL} : $cmd");
            $self->{retry}=1;
        } elsif ($cmd_error_code == -40401 || $cmd_error_code == -40407) {
            if ($self->{retry}) {
                printMsg("Token expired for $self->{BaseURL}, retrying : $cmd");
                $self->{retry}=0;
                $self->setToken();
                $self->sendCmd($cmd);
            } else {
                $self->{retry}=1;
            }
        } else {
            Error("Camera failed to execute command to $self->{BaseURL} : $cmd");
            Error(Dumper($response->content));
        }
        return 1;
    } else {
        Error("Command Fail");
        Error(Dumper($response->content));
        if ($self->{retry}) {
            $self->{retry}=0;
            $self->setToken();
            $self->sendCmd($cmd);
        } else {
            $self->{retry}=1;
            return 1;
        }
    }
}
### MOVE CONTINUOUS
sub moveConUp
{
    my $self = shift;
    printMsg("Move Con Up");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"0","y_coord":"'.$step.'"}}}');
}

sub moveConDown
{
    my $self = shift;
    printMsg("Move Con Down");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"0","y_coord":"-'.$step.'"}}}');
}

sub moveConLeft
{
    my $self = shift;
    printMsg("Move Con Left");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"-'.$step.'","y_coord":"0"}}}');
}

sub moveConRight
{
    my $self = shift;
    printMsg("Move Con Right");
    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"'.$step.'","y_coord":"0"}}}');
}

sub moveConUpRight
{
    my $self = shift;
    printMsg("Move Con Diagonally Up Right");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"'.$step.'","y_coord":"'.$step.'"}}}');
}

sub moveConDownRight
{
    my $self = shift;
    printMsg("Move Con Diagonally Down Right");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"'.$step.'","y_coord":"-'.$step.'"}}}');
}

sub moveConUpLeft
{
    my $self = shift;
    printMsg("Move Con Diagonally Up Left");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"-'.$step.'","y_coord":"'.$step.'"}}}');
}

sub moveConDownLeft
{
    my $self = shift;
    printMsg("Move Con Diagonally Down Left");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"-'.$step.'","y_coord":"-'.$step.'"}}}');
}

sub moveStop
{
    my $self = shift;
    printMsg("Move Con Stop");

    $self->sendCmd('{"method":"do","motor":{"stop":"null"}}');
}

### MOVE RELATIVE
sub moveRelUp
{
    my $self = shift;
    printMsg("Move ".$step." Up");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"0","y_coord":"'.$step.'"}}}');
}

sub moveRelDown
{
    my $self = shift;
    printMsg("Move ".$step." Down");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"0","y_coord":"-'.$step.'"}}}');
}

sub moveRelLeft
{
    my $self = shift;
    printMsg("Move ".$step." Left");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"-'.$step.'","y_coord":"0"}}}');
}

sub moveRelRight
{
    my $self = shift;
    printMsg("Move ".$step." Right");
    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"'.$step.'","y_coord":"0"}}}');
}

sub moveRelUpRight
{
    my $self = shift;
    printMsg("Move ".$step." Diagonally Up Right");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"'.$step.'","y_coord":"'.$step.'"}}}');
}

sub moveRelDownRight
{
    my $self = shift;
    printMsg("Move ".$step." Diagonally Down Right");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"'.$step.'","y_coord":"-'.$step.'"}}}');
}

sub moveRelUpLeft
{
    my $self = shift;
    printMsg("Move ".$step." Diagonally Up Left");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"-'.$step.'","y_coord":"'.$step.'"}}}');
}

sub moveRelDownLeft
{
    my $self = shift;
    printMsg("Move ".$step." Diagonally Down Left");

    $self->sendCmd('{"method":"do","motor":{"move":{"x_coord":"-'.$step.'","y_coord":"-'.$step.'"}}}');
}

sub presetGoto
{
    my $self = shift;
    my $params = shift;
    my $preset = $self->getParam($params, 'preset');
    printMsg("Go To Preset ".$preset);
    
    $self->sendCmd('{"method":"do","preset":{"goto_preset": {"id": "'.$preset.'"}}}');
}

sub presetSet
{
    my $self = shift;
    my $params = shift;
    my $preset = $self->getParam($params, 'preset');

    # Tapo C200 supports up to 8 presets
    if ($preset < 1 || $preset > 8) {
        Error("Invalid preset, it must be between 1 and 8', exiting");
        Exit(0);
    }

    my $dbh = zmDbConnect(1);
    my $sql = 'SELECT * FROM ControlPresets WHERE MonitorId = ? AND Preset = ?';
    my $sth = $dbh->prepare($sql);
    my $res = $sth->execute($self->{Monitor}->{Id}, $preset);
    my $ref = ($sth->fetchrow_hashref());
    my $label = $ref->{'Label'};

    printMsg("Set Preset '$preset' with label \"$label\"");

    # Remove preset, so we can update with the new data
    $self->sendCmd('{"method":"do","preset":{"remove_preset":{"id":['.$preset.']}}}');

    # Create/update preset
    $self->sendCmd('{"method":"do","preset":{"set_preset":{"id":"'.$preset.'","name":"'.$label.'","save_ptz":"1"}}}');
}

sub reset
{
    my $self = shift;

    if ($tapo_c200_debug == 1) {
        printMsg("Reloading controller for $self->{BaseURL}, exiting");
        Exit(0);
    } else {
        printMsg("Resetting position for $self->{BaseURL}");
        $self->sendCmd('{"method":"do","motor":{"manual_cali":"null"}}');
    }
}

sub reboot
{
    my $self = shift;
    printMsg("Rebooting $self->{BaseURL}");
    
    $self->sendCmd('{"method":"do","system":{"reboot":"null"}}');
}

sub wake
{
    my $self = shift;
    printMsg("Disabling Lens Mask for $self->{BaseURL}");
    
    $self->sendCmd('{"method":"set","lens_mask":{"lens_mask_info":{"enabled":"off"}}}');
}
 
sub sleep
{
    my $self = shift;
    printMsg("Enabling Lens Mask for $self->{BaseURL}");
    
    $self->sendCmd('{"method":"set","lens_mask":{"lens_mask_info":{"enabled":"on"}}}');
}

1;
