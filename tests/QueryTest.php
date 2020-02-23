<?php

error_reporting(E_ALL);
use Choval\Whois\Factory;
use Choval\Whois\Query;
use Clue\React\Block;
use PHPUnit\Framework\TestCase;

use React\EventLoop\Factory as LoopFactory;
use React\Promise\Promise;

use function Choval\Whois\ip_in_range;

class QueryTest extends TestCase
{
    public static $loop;



    /**
     * Loads a React Loop
     */
    public static function setUpBeforeClass(): void
    {
        static::$loop = LoopFactory::create();
        static::$loop->run();
    }



    /**
     * Wait for a promise (makes code synchronous) or stream (buffers)
     */
    private function wait($promise, $timeout = 5)
    {
        if ($promise instanceof \React\Promise\PromiseInterface) {
            return Block\await($promise, static::$loop, $timeout);
        } elseif (is_array($promise)) {
            return Block\awaitAll($promise, static::$loop, $timeout);
        }
        return $promise;
    }



    public function ipProvider()
    {
        return [
      [ '8.8.8.8', 'US', 'Level 3 Parent, LLC', 'ipv4' ],
      [ '13.77.161.179', 'US', 'Microsoft Corporation', 'ipv4' ],
      [ '31.13.85.36', 'IE', 'Facebook Ireland Ltd', 'ipv4' ],
      [ '194.224.110.41', 'ES', 'TDENET (Red de servicios IP)', 'ipv4' ],
      [ '124.74.250.145', 'CN', 'China Telecom', 'ipv4' ],
      [ '196.11.31.20', 'ZA', 'Bidorbuy (Pty) Ltd', 'ipv4' ],
      [ '2a03:2880:f11b:83:face:b00c:0:25', 'IE', 'Facebook Ireland Ltd', 'ipv6' ],
      [ '2001:4860:4860::8888', 'US', 'Google LLC', 'ipv6' ],
    ];
    }


    public function partialIpProvider()
    {
        return [
      [ '192.168.0', '192.168.0.0', 'ipv4' ],
      [ '2001:0db8::1428:57ab', '2001:0db8:0000:0000:0000:0000:1428:57ab', 'ipv6' ],
    ];
    }


    public function domainProvider()
    {
        return [
      ['google.com'],
      ['microsoft.com'],
    ];
    }


    public function singleProvider()
    {
        $ips = $this->ipProvider();
        $rand = array_rand($this->ipProvider());
        return [ $ips[$rand] ];
    }



    public function testInjection()
    {
        $this->expectException(\Exception::class);
        $q = new Query('8.8.8.8 && echo INJECTION');
        $raw = $q->run()->getRaw();
    }



    /**
     * @dataProvider ipProvider
     */
    public function testQueryAsync($ip, $country, $org)
    {
        $factory = new Factory(static::$loop);
        $query = $factory->create($ip);

        $this->assertInstanceOf(Query::class, $query);
        $this->assertEquals($ip, $query->getIp());

        $promise = $query->run();
        $this->assertInstanceOf(Promise::class, $promise);
        $res = static::wait($promise);
        $this->assertInstanceOf(Query::class, $res);

        $this->assertEquals($country, $query->getCountry());
        $this->assertEquals($org, $query->getOwner());

        $range = $query->getRange();
        $this->assertNotFalse($range);
        $inRange = ip_in_range($ip, $range['range']);
        $this->assertTrue($inRange);
    }



    /**
     * @dataProvider singleProvider
     */
    public function testQueryBlocking($ip, $country, $org)
    {
        $query = new Query($ip);
        $this->assertEquals($ip, $query->getIp());

        $query->run();

        $this->assertEquals($country, $query->getCountry());
        $this->assertEquals($org, $query->getOwner());
    }



    /**
     * @dataProvider domainProvider
     */
    public function testQueryDomain($domain)
    {
        $q = new Query($domain);
        $raw = $q->run()->getRaw();
        $this->assertNotEmpty($raw);
    }
}
