<?php

/**
 * This file is part of the Voonne platform (http://www.voonne.org)
 *
 * Copyright (c) 2016 Jan Lavička (mail@janlavicka.name)
 *
 * For the full copyright and license information, please view the file licence.md that was distributed with this source code.
 */

namespace Voonne\Security;

use Nette\Http\Session;
use Nette\SmartObject;
use Voonne\Voonne\Model\Entities\Domain;
use Voonne\Voonne\Model\Entities\DomainLanguage;
use Voonne\Voonne\Model\Repositories\DomainLanguageRepository;
use Voonne\Voonne\Model\Repositories\UserRepository;


class User
{

	use SmartObject;

	/**
	 * @var \Nette\Security\User
	 */
	private $user;

	/**
	 * @var Session
	 */
	private $session;

	/**
	 * @var UserRepository
	 */
	private $userRepository;

	/**
	 * @var DomainLanguageRepository
	 */
	private $domainLanguageRepository;


	public function __construct(
		\Nette\Security\User $user,
		Session $session,
		UserRepository $userRepository,
		DomainLanguageRepository $domainLanguageRepository
	)
	{
		$this->user = $user;
		$this->session = $session;
		$this->userRepository = $userRepository;
		$this->domainLanguageRepository = $domainLanguageRepository;
	}


	/**
	 * Returns entity of signed in user.
	 *
	 * @return \Voonne\Voonne\Model\Entities\User
	 *
	 * @throws InvalidStateException
	 */
	public function getUser()
	{
		if(!$this->user->isLoggedIn()) {
			throw new InvalidStateException('The user is not signed in.');
		}

		return $this->userRepository->find($this->user->getId());
	}


	/**
	 * Returns current domain language for edit.
	 *
	 * @return DomainLanguage
	 */
	public function getCurrentDomainLanguage()
	{
		$section = $this->session->getSection('voonne.domainLanguage');

		if(isset($section['id'])) {
			return $this->domainLanguageRepository->find($section['id']);
		} else {
			$domains = $this->domainLanguageRepository->findAll();

			if(count($domains) == 0) {
				throw new InvalidStateException('There was no registered domain.');
			}

			$section['id'] = $domains[0]->getId();

			return $domains[0];
		}
	}


	/**
	 * Returns current domain for edit.
	 *
	 * @return Domain
	 */
	public function getCurrentDomain()
	{
		return $this->getCurrentDomainLanguage()->getDomain();
	}


	/**
	 * Sets current domain language for edit.
	 *
	 * @param DomainLanguage $domainLanguage
	 */
	public function setCurrentDomainLanguage(DomainLanguage $domainLanguage)
	{
		$section = $this->session->getSection('voonne.domainLanguage');

		$section['id'] = $domainLanguage->getId();
	}

}
