<?php

/*
Copyright (c) 2015 LunaNode Hosting Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

namespace LunaNode;

class LunaNodeClient {
	static $LUNANODE_URL = 'https://dynamic.lunanode.com/api/{CATEGORY}/{ACTION}/';

	function __construct($api_id, $api_key) {
		if(strlen($api_id) != 16) {
			throw new LNAPIException('supplied api_id incorrect length, must be 16');
		}

		if(strlen($api_key) != 128) {
			throw new LNAPIException('supplied api_key incorrect length, must be 128');
		}

		$this->api_id = $api_id;
		$this->api_key = $api_key;
		$this->partial_api_key = substr($api_key, 0, 64);
	}

	public function request($category, $action, $params = array()) {
		$url = str_replace(array('{CATEGORY}', '{ACTION}'), array($category, $action), self::$LUNANODE_URL);
		$request_array = $params;
		$request_array['api_id'] = $this->api_id;
		$request_array['api_partialkey'] = $this->partial_api_key;
		$request_raw = json_encode($request_array);
		$nonce = time();
		$handler = "$category/$action/";
		$signature = hash_hmac('sha512', $handler . '|' . $request_raw . '|' . $nonce, $this->api_key);

		if($signature === false) {
			throw new LNAPIException('hash_hmac with sha512 failed');
		}

		$data = array(
			'req' => $request_raw,
			'signature' => $signature,
			'nonce' => $nonce
		);

		$options = array(
			'http' => array(
				'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
				'method'  => 'POST',
				'content' => http_build_query($data),
			)
		);
		$context  = stream_context_create($options);
		$result = file_get_contents($url, false, $context);
		if($result === false) {
			throw new LNAPIException('failed to perform HTTP request');
		}
		$response = json_decode($result, true);
		if(!$response) {
			throw new LNAPIException('server gave invalid response (could not decode)');
		} else if(!isset($response['success'])) {
			throw new LNAPIException('server gave invalid response (missing success key)');
		} else if($response['success'] !== 'yes') {
			if(isset($response['error'])) {
				throw new LNAPIException('API error: ' . $response['error']);
			} else {
				throw new LNAPIException('Unknown API error');
			}
		}
		return $response;
	}
}

class LNAPIException extends \Exception {}

?>
