<?php

namespace League\OAuth2\Client\Entity;

class User
{
    protected $sub;
    protected $name;
    protected $given_name;
    protected $family_name;
    protected $middle_name;
    protected $nickname;
    protected $preferred_username;
    protected $profile;
    protected $picture;
    protected $website;
    protected $email;
    protected $email_verified;
    protected $gender;
    protected $birthdate;
    protected $zoneinfo;
    protected $locale;
    protected $phone_number;
    protected $phone_number_verified;
    protected $address;
    protected $updated_at;

    public function __get($name)
    {
        if (!property_exists($this, $name)) {
            throw new \OutOfRangeException(sprintf(
                '%s does not contain a property by the name of "%s"',
                __CLASS__,
                $name
            ));
        }

        return $this->{$name};
    }

    public function __set($property, $value)
    {
        if (!property_exists($this, $property)) {
            throw new \OutOfRangeException(sprintf(
                '%s does not contain a property by the name of "%s"',
                __CLASS__,
                $property
            ));
        }

        $this->$property = $value;

        return $this;
    }

    public function __isset($name)
    {
        return (property_exists($this, $name));
    }

    public function getArrayCopy()
    {
        return [
            'sub' => $this->sub,
            'name' => $this->name,
            'given_name' => $this->given_name,
            'family_name' => $this->family_name,
            'middle_name' => $this->middle_name,
            'preferred_username' => $this->preferred_username,
            'profile' => $this->profile,
            'picture' => $this->picture,
            'website' => $this->website,
            'email' => $this->email,
            'email_verified' => $this->email_verified,
            'gender' => $this->gender,
            'birthdate' => $this->birthdate,
            'zoneinfo' => $this->zoneinfo,
            'locale' => $this->locale,
            'phone_number' => $this->phone_number,
            'phone_number_verified' => $this->phone_number_verified,
            'address' => $this->address,
            'updated_at' => $this->updated_at,
        ];
    }

    public function exchangeArray(array $data)
    {
        foreach ($data as $key => $value) {
            $key = strtolower($key);
            switch ($key) {
                case 'sub':
                    $this->sub = $value;
                    break;
                case 'name':
                    $this->name = $value;
                    break;
                case 'given_name':
                    $this->given_name = $value;
                    break;
                case 'family_name':
                    $this->family_name = $value;
                    break;
                case 'middle_name':
                    $this->middle_name = $value;
                    break;
                case 'nickname':
                    $this->nickname = $value;
                    break;
                case 'preferred_username':
                    $this->preferred_username = $value;
                    break;
                case 'profile':
                    $this->profile = $value;
                    break;
                case 'picture':
                    $this->picture = $value;
                    break;
                case 'website':
                    $this->website = $value;
                    break;
                case 'email':
                    $this->email = $value;
                    break;
                case 'email_verified':
                    $this->email_verified = $value;
                    break;
                case 'gender':
                    $this->gender = $value;
                    break;
                case 'birthdate':
                    $this->birthdate = $value;
                    break;
                case 'zoneinfo':
                    $this->zoneinfo = $value;
                    break;
                case 'locale':
                    $this->locale = $value;
                    break;
                case 'phone_number':
                    $this->phone_number = $value;
                    break;
                case 'phone_number_verified':
                    $this->phone_number_verified = $value;
                    break;
                case 'address':
                    $this->address = $value;
                    break;
                case 'updated_at':
                    $this->updated_at = $value;
                    break;
            }
        }

        return $this;
    }
}
