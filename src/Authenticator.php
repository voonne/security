<?php

/**
 * This file is part of the Voonne platform (http://www.voonne.org)
 *
 * Copyright (c) 2016 Jan Lavička (mail@janlavicka.name)
 *
 * For the full copyright and license information, please view the file licence.md that was distributed with this source code.
 */

namespace Voonne\Security;

use Nette\Security\Identity;
use Nette\Security\Passwords;
use Nette\SmartObject;
use Voonne\Model\IOException;
use Voonne\Voonne\Model\Repositories\UserRepository;


class Authenticator
{

	use SmartObject;

	/**
	 * @var \Nette\Security\User
	 */
	private $user;

	/**
	 * @var UserRepository
	 */
	private $userRepository;


	public function __construct(\Nette\Security\User $user, UserRepository $userRepository)
	{
		$this->user = $user;
		$this->userRepository = $userRepository;
	}


	/**
	 * @param string $email
	 * @param string $password
	 *
	 * @throws AuthenticationException
	 */
	function authenticate($email, $password)
	{
		try {
			$user = $this->userRepository->findOneBy(['email' => $email]);
		} catch (IOException $e) {
			throw new AuthenticationException('The requested user was not found.');
		}

		if (!Passwords::verify($password, $user->getPassword())) {
			throw new AuthenticationException('The password you entered is incorrect.');
		}

		$this->user->login(new Identity($user->getId()));
	}

}
