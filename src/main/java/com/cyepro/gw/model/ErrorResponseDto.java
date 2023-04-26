package com.cyepro.gw.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponseDto implements Serializable {

	private static final long serialVersionUID = -4878157986288629137L;

	private Date timestamp;
	private int status;
	private String error;
	private List<String> details;
	private String path;
}