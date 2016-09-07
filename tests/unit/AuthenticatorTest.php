<?php

namespace Voonne\TestSecurity;

use Codeception\Test\Unit;
use Mockery;
use Mockery\MockInterface;
use UnitTester;
use Voonne\Model\IOException;
use Voonne\Security\AuthenticationException;
use Voonne\Security\Authenticator;
use Voonne\Voonne\Model\Repositories\UserRepository;


class AuthenticatorTest extends Unit
{

	/**
	 * @var UnitTester
	 */
	protected $tester;

	/**
	 * @var MockInterface
	 */
	private $user;

	/**
	 * @var MockInterface
	 */
	private $userRepository;

	/**
	 * @var Authenticator
	 */
	private $authenticator;


	protected function _before()
	{
		$this->user = Mockery::mock(\Nette\Security\User::class);
		$this->userRepository = Mockery::mock(UserRepository::class);

		$this->authenticator = new Authenticator($this->user, $this->userRepository);
	}


	protected function _after()
	{
		Mockery::close();
	}


	public function testAuthenticate()
	{
		$user = Mockery::mock(\Voonne\Voonne\Model\Entities\User::class);

		$user->shouldReceive('getPassword')
			->once()
			->withNoArgs()
			->andReturn('$2y$10$JHDYJjWddFnBdo5jza7vRunAqWOqtZ3vJos92f5R0Vj3aPRNtvM0.');

		$user->shouldReceive('getId')
			->once()
			->withNoArgs()
			->andReturn('1');

		$this->userRepository->shouldReceive('findOneBy')
			->once()
			->with(['email' => 'john@example.com'])
			->andReturn($user);

		$this->user->shouldReceive('login')
			->once()
			->withAnyArgs();

		$this->authenticator->authenticate('john@example.com', 'password');
	}


	public function testAuthenticateUserDoNotExist()
	{
		$this->userRepository->shouldReceive('findOneBy')
			->once()
			->with(['email' => 'john@example.com'])
			->andThrow(IOException::class);

		$this->expectException(AuthenticationException::class);
		$this->authenticator->authenticate('john@example.com', 'password');
	}


	public function testAuthenticateBadPassword()
	{
		$user = Mockery::mock(\Voonne\Voonne\Model\Entities\User::class);

		$user->shouldReceive('getPassword')
			->once()
			->withNoArgs()
			->andReturn('badPassword');

		$this->userRepository->shouldReceive('findOneBy')
			->once()
			->with(['email' => 'john@example.com'])
			->andReturn($user);

		$this->expectException(AuthenticationException::class);
		$this->authenticator->authenticate('john@example.com', 'password');
	}

}
