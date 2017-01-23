<?php

namespace Voonne\TestSecurity;

use Codeception\Test\Unit;
use Doctrine\Common\Collections\ArrayCollection;
use Mockery;
use Mockery\MockInterface;
use Nette\Http\Session;
use UnitTester;
use Voonne\Security\Authorizator;
use Voonne\Security\InvalidStateException;
use Voonne\Security\User;
use Voonne\Voonne\Model\Entities\Domain;
use Voonne\Voonne\Model\Entities\Role;
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
	 * @var MockInterface
	 */
	private $authorizator;

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
		$this->authorizator = Mockery::mock(Authorizator::class);

		$this->securityUser = new User(
			$this->netteUser,
			$this->session,
			$this->userRepository,
			$this->domainRepository,
			$this->authorizator);
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


	public function testHaveArea()
	{
		$user = Mockery::mock(\Voonne\Voonne\Model\Entities\User::class);
		$role = Mockery::mock(Role::class);

		$this->netteUser->shouldReceive('isLoggedIn')
			->twice()
			->withNoArgs()
			->andReturn(true);

		$this->netteUser->shouldReceive('getId')
			->twice()
			->withNoArgs()
			->andReturn('1');

		$this->userRepository->shouldReceive('find')
			->twice()
			->with('1')
			->andReturn($user);

		$this->authorizator->shouldReceive('haveArea')
			->once()
			->with('front', ['guest'])
			->andReturn(true);

		$this->authorizator->shouldReceive('haveArea')
			->once()
			->with('admin', ['guest'])
			->andReturn(false);

		$user->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role]));

		$role->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('guest');

		$this->assertTrue($this->securityUser->haveArea('front'));
		$this->assertFalse($this->securityUser->haveArea('admin'));
	}


	public function testHaveResource()
	{
		$user = Mockery::mock(\Voonne\Voonne\Model\Entities\User::class);
		$role = Mockery::mock(Role::class);

		$this->netteUser->shouldReceive('isLoggedIn')
			->twice()
			->withNoArgs()
			->andReturn(true);

		$this->netteUser->shouldReceive('getId')
			->twice()
			->withNoArgs()
			->andReturn('1');

		$this->userRepository->shouldReceive('find')
			->twice()
			->with('1')
			->andReturn($user);

		$this->authorizator->shouldReceive('haveResource')
			->once()
			->with('admin', 'users', ['admin'])
			->andReturn(true);

		$this->authorizator->shouldReceive('haveResource')
			->once()
			->with('admin', 'roles', ['admin'])
			->andReturn(false);

		$user->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role]));

		$role->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$this->assertTrue($this->securityUser->haveResource('admin', 'users'));
		$this->assertFalse($this->securityUser->haveResource('admin', 'roles'));
	}


	public function testHavePrivilege()
	{
		$user = Mockery::mock(\Voonne\Voonne\Model\Entities\User::class);
		$role = Mockery::mock(Role::class);

		$this->netteUser->shouldReceive('isLoggedIn')
			->twice()
			->withNoArgs()
			->andReturn(true);

		$this->netteUser->shouldReceive('getId')
			->twice()
			->withNoArgs()
			->andReturn('1');

		$this->userRepository->shouldReceive('find')
			->twice()
			->with('1')
			->andReturn($user);

		$this->authorizator->shouldReceive('havePrivilege')
			->once()
			->with('admin', 'users', 'view', ['admin'])
			->andReturn(true);

		$this->authorizator->shouldReceive('havePrivilege')
			->once()
			->with('admin', 'users', 'create', ['admin'])
			->andReturn(false);

		$user->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role]));

		$role->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$this->assertTrue($this->securityUser->havePrivilege('admin', 'users', 'view'));
		$this->assertFalse($this->securityUser->havePrivilege('admin', 'users', 'create'));
	}

}
