<?php
/*
 * Form.class.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2004-2016 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015 Sjon Hortensius
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes software developed by the pfSense Project
 *    for use in the pfSense® software distribution. (http://www.pfsense.org/).
 *
 * 4. The names "pfSense" and "pfSense Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    coreteam@pfsense.org.
 *
 * 5. Products derived from this software may not be called "pfSense"
 *    nor may "pfSense" appear in their names without prior written
 *    permission of the Electric Sheep Fencing, LLC.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *
 * "This product includes software developed by the pfSense Project
 * for use in the pfSense software distribution (http://www.pfsense.org/).
 *
 * THIS SOFTWARE IS PROVIDED BY THE pfSense PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE pfSense PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

class Form extends Form_Element
{
	const LABEL_WIDTH = 2;
	const MAX_INPUT_WIDTH = 10;
	protected $_tagName = 'form';
	protected $_attributes = array(
		'class' => array('form-horizontal' => true),
		'method' => 'post',
	);
	protected $_sections = array();
	protected $_global = array();

	public function __construct($submit = null)
	{
		if (!isset($submit)) {
			$submit = gettext('Save');
		}

		if (gettype($submit) == 'string') {
			$submit = new Form_Button(
				'save',
				$submit,
				null,
				'fa-save'
			);
			$submit->addClass('btn-primary');
		}

		if (false !== $submit)
			$this->addGlobal($submit);

		if (!isset($this->_attributes['action']))
			$this->_attributes['action'] = $_SERVER['REQUEST_URI'];
	}

	public function add(Form_Section $section)
	{
		array_push($this->_sections, $section);
		$section->_setParent($this);

		return $section;
	}

	public function setAction($url)
	{
		$this->_attributes['action'] = $url;

		return $this;
	}

	public function addGlobal(Form_Input $input)
	{
		array_push($this->_global, $input);

		return $input;
	}

	public function setMultipartEncoding()
	{
		$this->_attributes['enctype'] = 'multipart/form-data';

		return $this;
	}

	protected function _setParent()
	{
		throw new Exception('Form does not have a parent');
	}

	public function __toString()
	{
		$element = parent::__toString();
		$html = implode('', $this->_sections);
		$buttons = '';

		foreach ($this->_global as $global)
		{
			if ($global instanceof Form_Button)
				$buttons .= $global;
			else
				$html .= $global;
		}

		if (!empty($buttons))
		{
			$group = new Form_Element;
			$group->addClass('col-sm-'. Form::MAX_INPUT_WIDTH, 'col-sm-offset-'. Form::LABEL_WIDTH);

			$html .= $group . $buttons .'</div>';
		}

		return <<<EOT
	{$element}
		{$html}
	</form>
EOT;
	}
}
