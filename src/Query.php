<?php

namespace Choval\Whois;

use Choval\Async;
use Choval\Whois;
use React\EventLoop\LoopInterface;

final class Query
{
    private $loop;
    private $timeout;

    private $addr;
    private $server;
    private $port;

    private $sections = [];
    private $lines = [];



    /**
     * Constructor
     */
    public function __construct(string $addr = null, string $server = null, int $port = null, LoopInterface $loop = null, float $timeout = 5)
    {
        if ($this->isVersion6($addr) || $this->isVersion4($addr)) {
            $this->addr = $addr;
        } else {
            $forbidden_chars = [' ', '|', '&', ':', '>', '<', '/', '\\', "\n", "\r", '"', '\'', ')', '(', '[', ']', '^', '~', '?', '=', ';', '`' ];
            foreach ($forbidden_chars as $char) {
                if (strpos($addr, $char) !== false) {
                    throw new \RuntimeException('Non valid address');
                }
            }
            $this->addr = $addr;
        }
        $this->server = null;
        $this->port = null;
        $this->loop = $loop;
        $this->timeout = $timeout;
    }



    /**
     * Builds the command to execute
     */
    private function getCommand()
    {
        return sprintf('which whois && whois %s %s %s', ($this->server ? '-h ' . $this->server : ''), ($this->port ? '-p ' . $this->port : ''), $this->addr);
    }



    /**
     * Runs a query
     */
    public function run()
    {
        return $this->query();
    }
    public function query()
    {
        $cmd = $this->getCommand();
        // Run in blocking mode if no loop
        if (empty($this->loop)) {
            exec($cmd, $lines);
            $this->sections = $this->parseSections($lines);
            $this->lines = $lines;
            return $this;
        }
        return Async\resolve(function () use ($cmd) {
            $res = yield Async\silent(Async\execute($this->loop, $cmd, $this->timeout));
            if ($res) {
                $lines = explode("\n", $res);
                $this->sections = $this->parseSections($lines);
                $this->lines = $lines;
            }
            return $this;
        });
    }



    /**
     * Parses the response from the WHOIS server
     */
    public function parseSections($response)
    {
        if (is_string($response)) {
            $response = explode("\n", $response);
        }
        $sections = [];
        $section = [];
        foreach ($response as $line) {
            $line = trim($line);
            if (empty($line) || in_array($line[0], ['%', '#'])) {
                if (!empty($section)) {
                    $sections[] = $section;
                    $section = [];
                }
                continue;
            }
            $parts = explode(':', $line, 2);
            $key = $parts[0];
            $data = trim($parts[1] ?? '');
            if (isset($section[$key])) {
                $section[$key] .= "\n" . $data;
            } else {
                $section[$key] = $data;
            }
        }
        return $sections;
    }



    /**
     * Parse data
     */
    public function parseData($lines, array $columns, bool $reverse = false)
    {
        if (is_string($lines)) {
            $lines = preg_split('/[\r\n]/', $lines);
        }
        if ($reverse) {
            $lines = array_reverse($lines);
        }
        foreach ($lines as $pos => $line) {
            $line = trim($line);
            if (is_numeric($pos)) {
                if (empty($line) || in_array($line[0], ['%', '#'])) {
                    continue;
                }
                $parts = explode(':', $line, 2);
                $key = strtolower(trim($parts[0]));
                $data = trim($parts[1] ?? '');
            } else {
                $key = $pos;
                $data = $line;
            }
            $lowdata = strtolower($data);
            if (in_array($key, $columns)) {
                return $data;
            }
        }
        return false;
    }



    /**
     * Returns the sections
     */
    public function getSections()
    {
        return $this->sections;
    }



    /**
     * Returns the raw response
     */
    public function getRaw()
    {
        return utf8_encode(implode("\n", $this->lines));
    }
    public function __toString()
    {
        return $this->getRaw();
    }



    /**
     * Gets the country from sections
     */
    public function getCountry()
    {
        $country = $this->parseData($this->lines, ['country', 'registrant country', 'domain']);
        if (!$country) {
            $parts = explode('.', $this->addr);
            $end = strtoupper(end($parts));
            if (strlen($end) == 2 && !is_numeric($end)) {
                return $end;
            }
            return;
        }
        return strtoupper($country);
    }



    /**
     * Gets the company
     */
    public function getOwner()
    {
        return $this->parseData($this->lines, ['organization', 'org-name', 'orgname', 'owner', 'descr', 'registrant organization', 'name', 'registrant name'], true);
    }



    /**
     * Gets the address
     */
    public function getIp()
    {
        return $this->addr;
    }
    public function getAddress()
    {
        return $this->addr;
    }



    /**
     * Returns boolean if its IPv6, otherwise its IPv4
     */
    public function isVersion6($ip = null)
    {
        return Whois\is_ipv6($ip ?? $this->addr);
    }
    public function isVersion4($ip = null)
    {
        return Whois\is_ipv6($ip ?? $this->addr);
    }



    /**
     * Returns the version
     */
    public function getVersion($ip = null)
    {
        return Whois\ip_version($ip ?? $this->addr, true);
    }



    /**
     * Gets the range from-to
     */
    public function getRange()
    {
        $range = $this->parseData($this->lines, ['inet6num', 'inetnum', 'route', 'netrange', 'cidr'], true);
        return $range ? Whois\parse_range($range) : false;
    }
}
