<?php

use Choval\Async;
use Choval\Whois\Factory;
use Choval\Whois\Query;
use PHPUnit\Framework\TestCase;

use React\EventLoop\Factory as LoopFactory;
use React\Promise\Promise;

use function Choval\Whois\ip2hex;
use function Choval\Whois\ip_expand;
use function Choval\Whois\ip_in_range;
use function Choval\Whois\ip_version;
use function Choval\Whois\is_ipv4;
use function Choval\Whois\is_ipv6;
use function Choval\Whois\parse_range;

class FunctionsTest extends TestCase
{
    public static $loop;



    /**
     * Loads a React Loop
     */
    public static function setUpBeforeClass(): void
    {
        static::$loop = Async\init();
    }



    /**
     * Wait for a promise (makes code synchronous) or stream (buffers)
     */
    private function wait($promise, $timeout = 5)
    {
        if ($promise instanceof \React\Promise\PromiseInterface) {
            return Async\wait($promise, $timeout);
        } elseif (is_array($promise)) {
            return Async\wait($promise, $timeout);
        }
        return $promise;
    }



    public function ipProvider()
    {
        return [
      [ '8.8.8.8', 'US', 'Google LLC (GOGL)', 'ipv4' ],
      [ '13.77.161.179', 'US', 'Microsoft Corporation (MSFT)', 'ipv4' ],
      [ '31.13.85.36', 'BR', 'Facebook', 'ipv4' ],
      [ '194.224.110.41', 'ES', 'Telefonica Soluciones', 'ipv4' ],
      [ '124.74.250.145', 'CN', 'CHINANET Shanghai province network', 'ipv4' ],
      [ '196.11.31.20', 'ZA', 'Bidorbuy (Pty) Ltd', 'ipv4' ],
      [ '2a03:2880:f11b:83:face:b00c:0:25', 'IE', 'Facebook Ireland Ltd', 'ipv6' ],
      [ '2001:4860:4860::8888', 'US', 'Google LLC (GOGL)', 'ipv6' ],
    ];
    }


    public function partialIpProvider()
    {
        return [
      [ '192.168.0', '192.168.0.0', 'ipv4' ],
      [ '2001:0db8::1428:57ab', '2001:0db8:0000:0000:0000:0000:1428:57ab', 'ipv6' ],
    ];
    }


    public function rangeProvider()
    {
        return [
      [ '124.74.0.0 - 124.75.255.255', '124.74.0.0', '124.75.255.255' ],
      [ '196.11.31.0 - 196.11.31.255', '196.11.31.0', '196.11.31.255' ],
      [ '186.19.128/18', '186.19.128.0', '186.19.191.255' ],
      [ '13.64.0.0 - 13.107.255.255', '13.64.0.0', '13.107.255.255' ],
      [ '2a03:2880::/29', '2a03:2880:0000:0000:0000:0000:0000:0000', '2a03:2887:ffff:ffff:ffff:ffff:ffff:ffff' ],
      [ '2001:4860:: - 2001:4860:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', '2001:4860:0000:0000:0000:0000:0000:0000', '2001:4860:ffff:ffff:ffff:ffff:ffff:ffff' ],
      [ '2001:4860::/32', '2001:4860:0000:0000:0000:0000:0000:0000', '2001:4860:ffff:ffff:ffff:ffff:ffff:ffff' ],
    ];
    }


    public function hexProvider()
    {
        return [
      [ '196.11.31.255', 'c40b1fff' ],
      [ '2a03:2880::', '2a032880000000000000000000000000' ],
    ];
    }




    /**
     * @dataProvider ipProvider
     */
    public function testIpVersion($ip, $a, $b, $version)
    {
        $v = ip_version($ip, true);
        $this->assertEquals($version, $v);

        if ($version == 'ipv4') {
            $this->assertTrue(is_ipv4($ip));
            $this->assertFalse(is_ipv6($ip));
        } elseif ($version == 'ipv6') {
            $this->assertTrue(is_ipv6($ip));
            $this->assertFalse(is_ipv4($ip));
        }
    }



    /**
     * @dataProvider partialIpProvider
     */
    public function testIpExpand($partial, $good)
    {
        $expanded = ip_expand($partial);
        $this->assertEquals($good, $expanded);
    }


    /**
     * @dataProvider hexProvider
     * @depends testIpExpand
     */
    public function testIp2Hex($ip, $hex)
    {
        $conv = ip2hex($ip);
        $this->assertEquals($hex, $conv);
    }


  
    /**
     * @dataProvider rangeProvider
     */
    public function testParseRange($range, $from, $to)
    {
        $limits = parse_range($range);
        $this->assertNotFalse($limits);
        $this->assertEquals($from, $limits['from']);
        $this->assertEquals($to, $limits['to']);
    }



    /**
     * @dataProvider rangeProvider
     */
    public function testIpInRange($range, $from, $to)
    {
        $this->assertTrue(ip_in_range($from, $range));
        $this->assertTrue(ip_in_range($to, $range));
    }
}
