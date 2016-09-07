<?php

namespace Voonne\TestSecurity;

use Codeception\Test\Unit;
use Mockery;
use Mockery\MockInterface;
use Nette\Http\Session;
use UnitTester;
use Voonne\Security\InvalidStateException;
use Voonne\Security\User;
use Voonne\Voonne\Model\Entities\DomainLanguage;
use Voonne\Voonne\Model\Repositories\DomainLanguageRepository;
use Voonne\Voonne\Model\Repositories\UserRepository;


class UserTest extends Unit
{

	/**
	 * @var UnitTester
	 */
	protected $tester;

	/**
	 * @var MockInterface
	 */
	private $netteUser;

	/**
	 * @var MockInterface
	 */
	private $session;

	/**
	 * @var MockInterface
	 */
	private $userRepository;

	/**
	 * @var MockInterface
	 */
	private $domainLanguageRepository;

	/**
	 * @var User
	 */
	private $securityUser;


	protected function _before()
	{
		$this->netteUser = Mockery::mock(\Nette\Security\User::class);
		$this->session = Mockery::mock(Session::class);
		$this->userRepository = Mockery::mock(UserRepository::class);
		$this->domainLanguageRepository = Mockery::mock(DomainLanguageRepository::class);

		$this->securityUser = new User(
			$this->netteUser,
			$this->session,
			$this->userRepository,
			$this->domainLanguageRepository
		);
	}


	protected function _after()
	{
		Mockery::close();
	}


	public function testGetUser()
	{
		$user = Mockery::mock(\Voonne\Voonne\Model\Entities\User::class);

		$this->netteUser->shouldReceive('isLoggedIn')
			->once()
			->withNoArgs()
			->andReturn(true);

		$this->netteUser->shouldReceive('getId')
			->once()
			->withNoArgs()
			->andReturn('1');

		$this->userRepository->shouldReceive('find')
			->once()
			->with('1')
			->andReturn($user);

		$this->assertEquals($user, $this->securityUser->getUser());
	}


	public function testGetUserIsNotSignedIn()
	{
		$this->netteUser->shouldReceive('isLoggedIn')
			->once()
			->withNoArgs()
			->andReturn(false);

		$this->expectException(InvalidStateException::class);
		$this->securityUser->getUser();
	}


	public function testGetCurrentDomainLanguageSelected()
	{
		$domainLanguage = Mockery::mock(DomainLanguage::class);

		$this->session->shouldReceive('getSection')
			->once()
			->with('voonne.domainLanguage')
			->andReturn(['id' => '1']);

		$this->domainLanguageRepository->shouldReceive('find')
			->once()
			->with('1')
			->andReturn($domainLanguage);

		$this->assertEquals($domainLanguage, $this->securityUser->getCurrentDomainLanguage());
	}


	public function testGetCurrentDomainLanguageNotSelected()
	{
		$domainLanguage1 = Mockery::mock(DomainLanguage::class);
		$domainLanguage2 = Mockery::mock(DomainLanguage::class);

		$domainLanguage1->shouldReceive('getId')
			->once()
			->withNoArgs()
			->andReturn('1');

		$this->session->shouldReceive('getSection')
			->once()
			->with('voonne.domainLanguage')
			->andReturn([]);

		$this->domainLanguageRepository->shouldReceive('findAll')
			->once()
			->withNoArgs()
			->andReturn([$domainLanguage1, $domainLanguage2]);

		$this->assertEquals($domainLanguage1, $this->securityUser->getCurrentDomainLanguage());
	}


	public function testSetCurrentDomainLanguage()
	{
		$domainLanguage = Mockery::mock(DomainLanguage::class);

		$domainLanguage->shouldReceive('getId')
			->once()
			->withNoArgs()
			->andReturn('1');

		$this->session->shouldReceive('getSection')
			->once()
			->with('voonne.domainLanguage')
			->andReturn([]);

		$this->securityUser->setCurrentDomainLanguage($domainLanguage);
	}

}
