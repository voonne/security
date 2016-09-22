<?php

namespace Voonne\TestSecurity;

use Codeception\Test\Unit;
use Mockery;
use Mockery\MockInterface;
use Nette\Http\Session;
use UnitTester;
use Voonne\Security\InvalidStateException;
use Voonne\Security\User;
use Voonne\Voonne\Model\Entities\Domain;
use Voonne\Voonne\Model\Repositories\DomainRepository;
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
	private $domainRepository;

	/**
	 * @var User
	 */
	private $securityUser;


	protected function _before()
	{
		$this->netteUser = Mockery::mock(\Nette\Security\User::class);
		$this->session = Mockery::mock(Session::class);
		$this->userRepository = Mockery::mock(UserRepository::class);
		$this->domainRepository = Mockery::mock(DomainRepository::class);

		$this->securityUser = new User(
			$this->netteUser,
			$this->session,
			$this->userRepository,
			$this->domainRepository
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


	public function testGetCurrentDomainSelected()
	{
		$domain = Mockery::mock(Domain::class);

		$this->session->shouldReceive('getSection')
			->once()
			->with('voonne.domain')
			->andReturn(['id' => '1']);

		$this->domainRepository->shouldReceive('find')
			->once()
			->with('1')
			->andReturn($domain);

		$this->assertEquals($domain, $this->securityUser->getCurrentDomain());
	}


	public function testGetCurrentDomainNotSelected()
	{
		$domain1 = Mockery::mock(Domain::class);
		$domain2 = Mockery::mock(Domain::class);

		$this->session->shouldReceive('getSection')
			->once()
			->with('voonne.domain')
			->andReturn([]);

		$this->domainRepository->shouldReceive('findAll')
			->once()
			->withNoArgs()
			->andReturn([$domain1, $domain2]);

		$this->assertEquals($domain1, $this->securityUser->getCurrentDomain());
	}


	public function testSetCurrentDomain()
	{
		$domain = Mockery::mock(Domain::class);

		$this->session->shouldReceive('getSection')
			->once()
			->with('voonne.domain')
			->andReturn([]);

		$this->securityUser->setCurrentDomain($domain);
	}

}
