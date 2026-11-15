// Intentionally vulnerable NestJS controller (academic SAST target).
import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { execSync } from 'child_process';
import { DataSource } from 'typeorm';

const escape = (s: string) => s.replace(/[&<>"']/g, '');

@Controller('users')
export class UsersController {
  constructor(private readonly dataSource: DataSource) {}

  @Get('search')
  async search(@Query('name') name: string) {
    return this.dataSource.query(`SELECT * FROM users WHERE name = '${name}'`); // VULN: SQL injection
  }

  @Get('greet')
  greet(@Query('who') who: string): string {
    return '<h1>Hello ' + who + '</h1>';                                       // VULN: reflected XSS
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.dataSource.query('SELECT * FROM users WHERE id = ' + id);      // VULN: SQL injection (path)
  }

  @Post('run')
  run(@Body('cmd') cmd: string) {
    return execSync(cmd).toString();                                           // VULN: command injection
  }

  // --- safe counterparts -----------------------------------------------------
  @Get('safe/search')
  safeSearch(@Query('name') name: string) {
    return this.dataSource.query('SELECT * FROM users WHERE name = $1', [name]); // parameterized -> safe
  }

  @Get('safe/greet')
  safeGreet(@Query('who') who: string): string {
    return `<h1>Hello ${escape(who)}</h1>`;                                     // escaped -> safe
  }
}
