<?php

/*
 * This file is part of the ACME PHP library.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Ssl\Signer;

use AcmePhp\Ssl\Exception\DataSigningException;
use AcmePhp\Ssl\PrivateKey;

/**
 * Provide tools to sign data using a private key.
 *
 * @author Titouan Galopin <galopintitouan@gmail.com>
 */
class DataSigner
{
    /**
     * Generate a signature of the given data using a private key and an algorithm.
     *
     * @param string     $data
     * @param PrivateKey $privateKey
     * @param int        $algorithm
     *
     * @return string
     */
    public function signData($data, PrivateKey $privateKey, $algorithm = OPENSSL_ALGO_SHA256)
    {
        $resource = $privateKey->getResource();
        if (!openssl_sign($data, $signature, $resource, $algorithm)) {
            throw new DataSigningException(sprintf('OpenSSL data signing failed with error: %s', openssl_error_string()));
        }

        openssl_free_key($resource);

        return $signature;
    }
}
