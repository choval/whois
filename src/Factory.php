<?php

namespace Choval\Whois;

use Choval\Whois\Query;
use React\EventLoop\LoopInterface;

class Factory
{
    private $loop;
    private $timeout;


    /**
     * Constructor
     */
    public function __construct(LoopInterface $loop, float $timeout = 3)
    {
        $this->loop = $loop;
        $this->timeout = $timeout;
    }


    /**
     * Creates a query
     */
    public function query(string $addr, string $server = null, int $port = null)
    {
        return new Query($addr, $server, $port, $this->loop);
    }
    public function create(string $addr, string $server = null, int $port = null)
    {
        return $this->query($addr, $server, $port);
    }


    /**
     * Get the loop
     */
    public function getLoop()
    {
        return $this->loop;
    }


    /**
     * Gets the timeout
     */
    public function getTimeout()
    {
        return $this->timeout;
    }
}
