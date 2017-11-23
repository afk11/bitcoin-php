<?php
/**
 * Created by PhpStorm.
 * User: tk
 * Date: 11/18/17
 * Time: 6:59 PM
 */

namespace BitWasp\Bitcoin\Transaction\Factory\Matcher\InputType;


class FixedLengthBlob extends DataBlob
{
    /**
     * @var int
     */
    private $length;

    /**
     * FixedLengthBlob constructor.
     * @param int $length
     */
    public function __construct($length) {
        $this->length = $length;
    }

    /**
     * @return int
     */
    public function getLength() {
        return $this->length;
    }
}
